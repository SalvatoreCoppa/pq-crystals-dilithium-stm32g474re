#include <stdint.h>
#include "params.h"
#include "sign.h"
#include "packing.h"
#include "polyvec.h"
#include "poly.h"
#include "randombytes.h"
#include "symmetric.h"
#include "fips202.h"

/*************************************************
* Nome:        crypto_sign_keypair
*
* Descrizione: Genera una coppia di chiavi pubblica e privata per ML-DSA (Dilithium)
*
* Argomenti:   - uint8_t *pk: puntatore alla chiave pubblica in output
*                                (array allocato di CRYPTO_PUBLICKEYBYTES byte)
*              - uint8_t *sk: puntatore alla chiave segreta in output
*                                (array allocato di CRYPTO_SECRETKEYBYTES byte)
*
* Ritorna:     0 (successo)
**************************************************/
int crypto_sign_keypair(uint8_t *pk, uint8_t *sk) {
  // Buffer per contenere semi casuali: rho || rhoprime || key
  uint8_t seedbuf[2*SEEDBYTES + CRHBYTES];	// 128 bit
  uint8_t tr[TRBYTES];  // Digest H(pk) da includere nella chiave segreta
  const uint8_t *rho, *rhoprime, *key;

  // Matrice A e vettori della chiave
  polyvecl mat[K];
  polyvecl s1, s1hat;
  polyveck s2, t1, t0;

  /*************************************************
  * STEP 1: Generazione del seme iniziale
  * seedbuf conterrà ρ (rho), ρ′ (rhoprime), key
  *************************************************/
  randombytes(seedbuf, SEEDBYTES);  // Entropia casuale dal generatore
  // Aggiunta di K e L per domain separation tra varianti di Dilithium.
  // Garantisce che rho, rhoprime e key siano distinti anche con lo stesso seed.
  seedbuf[SEEDBYTES+0] = K;         // Domini separati per evitare collisioni
  seedbuf[SEEDBYTES+1] = L;
  shake256(seedbuf, 2*SEEDBYTES + CRHBYTES, seedbuf, SEEDBYTES+2);

  rho      = seedbuf;                 // ρ → input per generare la matrice pubblica A
  rhoprime = rho + SEEDBYTES;        // ρ′ → input per il campionamento dei vettori s1, s2
  key      = rhoprime + CRHBYTES;    // K  → chiave segreta randomica ausiliaria

  /*************************************************
  * STEP 2: Espansione della matrice pubblica A
  * Viene costruita da ρ con espansione deterministica
  *************************************************/
  polyvec_matrix_expand(mat, rho);

  /*************************************************
  * STEP 3: Campionamento dei vettori s1 (secret) e s2 (errore)
  * Usano η-distribution per generare piccoli coefficienti
  *************************************************/
  polyvecl_uniform_eta(&s1, rhoprime, 0);     // s1 ∈ R_q^L (vettore segreto)
  polyveck_uniform_eta(&s2, rhoprime, L);     // s2 ∈ R_q^K (vettore di errore)

  /*************************************************
  * STEP 4: Moltiplicazione A·s1 e somma con s2
  * Viene calcolato t = A·s1 + s2
  * Nota: s1 viene trasformato in dominio NTT per ottimizzare il prodotto
  *************************************************/
  s1hat = s1;
  polyvecl_ntt(&s1hat);                         // NTT(s1)
  polyvec_matrix_pointwise_montgomery(&t1, mat, &s1hat); // t1 = A·s1
  polyveck_reduce(&t1);                         // riduzione modulo q
  polyveck_invntt_tomont(&t1);                  // ritorno da dominio NTT

  polyveck_add(&t1, &t1, &s2);                  // t1 = A·s1 + s2

  /*************************************************
  * STEP 5: Rounding e separazione t1 = t1_high || t1_low
  * t1 viene separato in due componenti per proteggere s1 e s2
  *************************************************/
  polyveck_caddq(&t1);                          // centratura modulo q
  polyveck_power2round(&t1, &t0, &t1);          // t1 = t1_high, t0 = t1_low

  /*************************************************
  * STEP 6: Packing della chiave pubblica
  * pk = (ρ, t1)
  *************************************************/
  pack_pk(pk, rho, &t1);

  /*************************************************
  * STEP 7: Hash della chiave pubblica
  * tr = H(pk) → usato nella firma per il commitment
  *************************************************/
  shake256(tr, TRBYTES, pk, CRYPTO_PUBLICKEYBYTES);

  /*************************************************
  * STEP 8: Packing della chiave segreta
  * sk = (ρ, tr, key, t0, s1, s2)
  *************************************************/
  pack_sk(sk, rho, tr, key, &t0, &s1, &s2);

  return 0;
}


/*************************************************
* Nome:        crypto_sign_signature_internal
*
* Descrizione: Calcola una firma digitale per un messaggio.
*              È un’API interna usata da crypto_sign_signature.
*
* Argomenti:   - uint8_t *sig:     buffer di output per la firma (lunghezza CRYPTO_BYTES)
*              - size_t *siglen:   lunghezza effettiva della firma (CRYPTO_BYTES)
*              - uint8_t *m:       messaggio da firmare
*              - size_t mlen:      lunghezza del messaggio
*              - uint8_t *pre:     prefisso opzionale (es. per contestualizzare la firma)
*              - size_t prelen:    lunghezza del prefisso
*              - uint8_t *rnd:     seme randomico per derandomizzazione della firma
*              - uint8_t *sk:      chiave segreta (impacchettata)
*
* Ritorna:     0 (successo)
**************************************************/
int crypto_sign_signature_internal(uint8_t *sig,
                                   size_t *siglen,
                                   const uint8_t *m,
                                   size_t mlen,
                                   const uint8_t *pre,
                                   size_t prelen,
                                   const uint8_t rnd[RNDBYTES],
                                   const uint8_t *sk)
{
  // Variabili e buffer
  unsigned int n;
  uint8_t seedbuf[2*SEEDBYTES + TRBYTES + 2*CRHBYTES];  // buffer temporaneo
  uint8_t *rho, *tr, *key, *mu, *rhoprime;
  uint16_t nonce = 0;

  // Vettori e polinomi secondo lo schema Dilithium
  polyvecl mat[K], s1, y, z;
  polyveck t0, s2, w1, w0, h;
  poly cp;
  keccak_state state;

  // Mappatura dei puntatori nel buffer unico
  rho      = seedbuf;
  tr       = rho + SEEDBYTES;
  key      = tr + TRBYTES;
  mu       = key + SEEDBYTES;
  rhoprime = mu + CRHBYTES;

  // Estrazione delle componenti della chiave segreta
  unpack_sk(rho, tr, key, &t0, &s1, &s2, sk);

  /*************************************************
  * STEP 1: Calcolo del messaggio hashato (mu)
  * mu = H(tr || prefix || message)
  * Serve a impegnarsi sul contenuto del messaggio da firmare
  *************************************************/
  shake256_init(&state);
  shake256_absorb(&state, tr, TRBYTES);
  shake256_absorb(&state, pre, prelen);
  shake256_absorb(&state, m, mlen);
  shake256_finalize(&state);
  shake256_squeeze(mu, CRHBYTES, &state);

  /*************************************************
  * STEP 2: Derivazione di rhoprime (ρ'')
  * rhoprime = H(key || rnd || mu)
  * Determina i vettori casuali interni in modo unico per ogni firma
  *************************************************/
  shake256_init(&state);
  shake256_absorb(&state, key, SEEDBYTES);
  shake256_absorb(&state, rnd, RNDBYTES);
  shake256_absorb(&state, mu, CRHBYTES);
  shake256_finalize(&state);
  shake256_squeeze(rhoprime, CRHBYTES, &state);

  /*************************************************
  * STEP 3: Espansione della matrice A
  * e trasformazione NTT dei vettori segreti
  *************************************************/
  polyvec_matrix_expand(mat, rho);
  polyvecl_ntt(&s1);
  polyveck_ntt(&s2);
  polyveck_ntt(&t0);

rej:
  /*************************************************
  * STEP 4: Campionamento vettore y
  * y ~ Distribuzione uniforme in Gamma1
  *************************************************/
  polyvecl_uniform_gamma1(&y, rhoprime, nonce++);

  /*************************************************
  * STEP 5: Calcolo w = A·y
  *************************************************/
  z = y;
  polyvecl_ntt(&z);
  polyvec_matrix_pointwise_montgomery(&w1, mat, &z);
  polyveck_reduce(&w1);
  polyveck_invntt_tomont(&w1);

  /*************************************************
  * STEP 6: Decomposizione w e calcolo della sfida (challenge)
  *************************************************/
  polyveck_caddq(&w1);
  polyveck_decompose(&w1, &w0, &w1);
  polyveck_pack_w1(sig, &w1);  // si usa lo spazio di sig temporaneamente

  // Costruzione della sfida c = H(mu || w1)
  shake256_init(&state);
  shake256_absorb(&state, mu, CRHBYTES);
  shake256_absorb(&state, sig, K*POLYW1_PACKEDBYTES);
  shake256_finalize(&state);
  shake256_squeeze(sig, CTILDEBYTES, &state);
  poly_challenge(&cp, sig);
  poly_ntt(&cp);

  /*************************************************
  * STEP 7: Calcolo z = y + c·s1
  * Deve rispettare vincoli per non rivelare s1
  *************************************************/
  polyvecl_pointwise_poly_montgomery(&z, &cp, &s1);
  polyvecl_invntt_tomont(&z);
  polyvecl_add(&z, &z, &y);
  polyvecl_reduce(&z);
  if(polyvecl_chknorm(&z, GAMMA1 - BETA))
    goto rej;  // Firma scartata → rischio di leak su s1

  /*************************************************
  * STEP 8: Verifica che w0 - c·s2 non riveli info
  *************************************************/
  polyveck_pointwise_poly_montgomery(&h, &cp, &s2);
  polyveck_invntt_tomont(&h);
  polyveck_sub(&w0, &w0, &h);
  polyveck_reduce(&w0);
  if(polyveck_chknorm(&w0, GAMMA2 - BETA))
    goto rej;

  /*************************************************
  * STEP 9: Calcolo dei "hint" h da t0
  * Serve per permettere la verifica di w1 ≈ A·z - c·t1
  *************************************************/
  polyveck_pointwise_poly_montgomery(&h, &cp, &t0);
  polyveck_invntt_tomont(&h);
  polyveck_reduce(&h);
  if(polyveck_chknorm(&h, GAMMA2))
    goto rej;

  polyveck_add(&w0, &w0, &h);
  n = polyveck_make_hint(&h, &w0, &w1);
  if(n > OMEGA)
    goto rej;

  /*************************************************
  * STEP 10: Composizione della firma finale
  * sig = (c, z, h)
  *************************************************/
  pack_sig(sig, sig, &z, &h);
  *siglen = CRYPTO_BYTES;
  return 0;
}


/*************************************************
* Nome:        crypto_sign_signature
*
* Descrizione: Calcola la firma digitale del messaggio `m`
*              usando la chiave segreta `sk`.
*
* Argomenti:   - uint8_t *sig:     buffer di output per la firma (CRYPTO_BYTES)
*              - size_t *siglen:   lunghezza della firma generata
*              - uint8_t *m:       messaggio da firmare
*              - size_t mlen:      lunghezza del messaggio
*              - uint8_t *ctx:     stringa di contesto opzionale
*              - size_t ctxlen:    lunghezza del contesto
*              - uint8_t *sk:      chiave segreta (bit-packed)
*
* Ritorna:     0  → firma generata con successo
*              -1 → errore: contesto troppo lungo
**************************************************/
int crypto_sign_signature(uint8_t *sig,
                          size_t *siglen,
                          const uint8_t *m,
                          size_t mlen,
                          const uint8_t *ctx,
                          size_t ctxlen,
                          const uint8_t *sk)
{
  size_t i;
  uint8_t pre[257];         // prefisso pre = [flag, ctxlen, ctx...] (max 255 di contesto)
  uint8_t rnd[RNDBYTES];    // random seed per la firma (usato se randomized signing attivo)

  // Controllo di sicurezza: il contesto non può superare 255 byte
  if(ctxlen > 255)
    return -1;

  /*************************************************
  * STEP 1: Costruzione del prefisso `pre`
  * pre = [0, ctxlen, ctx...] → usato come parte del commitment
  * Serve per evitare riutilizzo della stessa firma in contesti diversi (domain separation)
  *************************************************/
  pre[0] = 0;         // flag = 0 → signature (1 significherebbe altro tipo, es. KEM)
  pre[1] = ctxlen;    // lunghezza del contesto
  for(i = 0; i < ctxlen; i++)
    pre[2 + i] = ctx[i];

  /*************************************************
  * STEP 2: Generazione del seme casuale `rnd`
  * se la firma è "hedged" → usa RNG
  * altrimenti `rnd = 0` per firma deterministica
  *************************************************/
#ifdef DILITHIUM_RANDOMIZED_SIGNING  // flag definito in params.h o config
  randombytes(rnd, RNDBYTES);        // firma casuale → più sicura se RNG è affidabile
#else
  for(i = 0; i < RNDBYTES; i++)
    rnd[i] = 0;                      // fallback deterministico (per test o ambienti critici)
#endif

  /*************************************************
  * STEP 3: Invocazione del motore interno di firma
  * Tutta la logica vera della firma è in crypto_sign_signature_internal()
  *************************************************/
  crypto_sign_signature_internal(sig, siglen, m, mlen, pre, 2 + ctxlen, rnd, sk);

  return 0;
}

/*************************************************
* Nome:        crypto_sign
*
* Descrizione: Calcola una firma digitale per `m` e restituisce `sig || m`
*              in un singolo buffer.
*              Questa è l’interfaccia compatibile con le API NaCl-style.
*
* Argomenti:
*    - uint8_t *sm:     buffer di output per [firma || messaggio]
*                       deve avere almeno CRYPTO_BYTES + mlen byte
*    - size_t *smlen:   lunghezza totale dell'output (firma + messaggio)
*    - const uint8_t *m: messaggio da firmare
*    - size_t mlen:     lunghezza del messaggio
*    - const uint8_t *ctx: stringa di contesto (opzionale)
*    - size_t ctxlen:   lunghezza del contesto
*    - const uint8_t *sk: chiave segreta (bit-packed)
*
* Ritorna: 0 (successo), -1 se ctx troppo lungo
**************************************************/
int crypto_sign(uint8_t *sm,
                size_t *smlen,
                const uint8_t *m,
                size_t mlen,
                const uint8_t *ctx,
                size_t ctxlen,
                const uint8_t *sk)
{
  int ret;
  size_t i;

  /*************************************************
  * STEP 1: Copia il messaggio in fondo al buffer di output
  * Il messaggio viene spostato in `sm + CRYPTO_BYTES`
  * così `sm[0..CRYPTO_BYTES-1]` resta libero per la firma
  *************************************************/
  for(i = 0; i < mlen; ++i)
    sm[CRYPTO_BYTES + mlen - 1 - i] = m[mlen - 1 - i];

  /*************************************************
  * STEP 2: Firma il messaggio (ora in `sm + CRYPTO_BYTES`)
  * La firma viene scritta in `sm[0..CRYPTO_BYTES-1]`
  *************************************************/
  ret = crypto_sign_signature(
           sm,            // ← scrive qui la firma
           smlen,         // ← lunghezza iniziale della firma (CRYPTO_BYTES)
           sm + CRYPTO_BYTES, // ← messaggio da firmare
           mlen,
           ctx, ctxlen,
           sk);

  /*************************************************
  * STEP 3: Aggiungi lunghezza del messaggio
  * Ora *smlen = lunghezza totale = firma + messaggio
  *************************************************/
  *smlen += mlen;

  return ret;
}


/*************************************************
* Nome:        crypto_sign_verify_internal
*
* Descrizione: Verifica la firma su un messaggio.
*              È l'API interna usata da `crypto_sign_verify`.
*
* Argomenti:
*    - const uint8_t *sig:   firma ricevuta (CRYPTO_BYTES)
*    - size_t siglen:        lunghezza della firma (deve essere esattamente CRYPTO_BYTES)
*    - const uint8_t *m:     messaggio originale
*    - size_t mlen:          lunghezza del messaggio
*    - const uint8_t *pre:   prefisso (context, separazione di dominio)
*    - size_t prelen:        lunghezza del prefisso
*    - const uint8_t *pk:    chiave pubblica bit-packed
*
* Ritorna: 0 se la firma è valida, -1 altrimenti
**************************************************/
int crypto_sign_verify_internal(const uint8_t *sig,
                                size_t siglen,
                                const uint8_t *m,
                                size_t mlen,
                                const uint8_t *pre,
                                size_t prelen,
                                const uint8_t *pk)
{
  unsigned int i;

  // Buffer temporanei
  uint8_t buf[K * POLYW1_PACKEDBYTES];  // per w1 ricostruito
  uint8_t rho[SEEDBYTES];               // seme della matrice A
  uint8_t mu[CRHBYTES];                 // hash tr||ctx||msg
  uint8_t c[CTILDEBYTES];               // challenge dalla firma
  uint8_t c2[CTILDEBYTES];              // challenge ricostruita

  // Polinomi
  poly cp;
  polyvecl mat[K], z;
  polyveck t1, w1, h;

  keccak_state state;

  /*************************************************
  * STEP 0: Controllo della lunghezza
  *************************************************/
  if(siglen != CRYPTO_BYTES)
    return -1;

  /*************************************************
  * STEP 1: Estrazione della chiave pubblica
  * pk = (rho, t1)
  *************************************************/
  unpack_pk(rho, &t1, pk);

  /*************************************************
  * STEP 2: Estrazione della firma
  * sig = (c, z, h)
  *************************************************/
  if(unpack_sig(c, &z, &h, sig))
    return -1;

  // Controllo di sicurezza: norm(z) < γ₁ - β
  if(polyvecl_chknorm(&z, GAMMA1 - BETA))
    return -1;

  /*************************************************
  * STEP 3: Calcolo di mu = CRH(H(pk), ctx, msg)
  *************************************************/
  shake256(mu, TRBYTES, pk, CRYPTO_PUBLICKEYBYTES); // tr = H(pk)
  shake256_init(&state);
  shake256_absorb(&state, mu, TRBYTES);
  shake256_absorb(&state, pre, prelen);
  shake256_absorb(&state, m, mlen);
  shake256_finalize(&state);
  shake256_squeeze(mu, CRHBYTES, &state);

  /*************************************************
  * STEP 4: Ricostruzione w1 = Az - c·t1
  *************************************************/
  poly_challenge(&cp, c);            // challenge → polinomio
  polyvec_matrix_expand(mat, rho);   // ricrea matrice A da rho

  polyvecl_ntt(&z);                                 // z → dominio NTT
  polyvec_matrix_pointwise_montgomery(&w1, mat, &z); // w1 = A·z

  poly_ntt(&cp);
  polyveck_shiftl(&t1);             // t1 <<= D
  polyveck_ntt(&t1);
  polyveck_pointwise_poly_montgomery(&t1, &cp, &t1); // t1 = c·t1

  polyveck_sub(&w1, &w1, &t1);       // w1 = Az - c·t1
  polyveck_reduce(&w1);
  polyveck_invntt_tomont(&w1);       // torna da NTT

  /*************************************************
  * STEP 5: Ricostruzione di w1 usando gli hint h
  * La parte alta w1 viene corretta per ottenere il valore esatto
  *************************************************/
  polyveck_caddq(&w1);
  polyveck_use_hint(&w1, &w1, &h);   // usa h per correggere w1
  polyveck_pack_w1(buf, &w1);        // impacchetta w1 in buf[]

  /*************************************************
  * STEP 6: Ricostruzione di c' = H(mu || w1)
  * deve essere uguale a c se la firma è corretta
  *************************************************/
  shake256_init(&state);
  shake256_absorb(&state, mu, CRHBYTES);
  shake256_absorb(&state, buf, K * POLYW1_PACKEDBYTES);
  shake256_finalize(&state);
  shake256_squeeze(c2, CTILDEBYTES, &state);

  // Verifica che la challenge rigenerata sia uguale a quella firmata
  for(i = 0; i < CTILDEBYTES; ++i)
    if(c[i] != c2[i])
      return -1;

  return 0;  // firma valida
}


/*************************************************
* Nome:        crypto_sign_verify
*
* Descrizione: Verifica una firma su un messaggio usando la chiave pubblica.
*              Versione esterna che prepara il contesto e chiama l'API interna.
*
* Argomenti:
*    - const uint8_t *sig:   firma (CRYPTO_BYTES)
*    - size_t siglen:        lunghezza della firma
*    - const uint8_t *m:     messaggio originale
*    - size_t mlen:          lunghezza del messaggio
*    - const uint8_t *ctx:   contesto (opzionale)
*    - size_t ctxlen:        lunghezza del contesto
*    - const uint8_t *pk:    chiave pubblica
*
* Ritorna: 0 se la firma è valida, -1 altrimenti
**************************************************/
int crypto_sign_verify(const uint8_t *sig,
                       size_t siglen,
                       const uint8_t *m,
                       size_t mlen,
                       const uint8_t *ctx,
                       size_t ctxlen,
                       const uint8_t *pk)
{
  size_t i;
  uint8_t pre[257];  // prefisso (flag, ctxlen, ctx)

  // Verifica che il contesto non sia troppo lungo
  if(ctxlen > 255)
    return -1;

  // Costruzione del prefisso per domain separation
  pre[0] = 0;        // flag (0 = firma)
  pre[1] = ctxlen;
  for(i = 0; i < ctxlen; i++)
    pre[2 + i] = ctx[i];

  // Chiamata alla funzione di verifica interna
  return crypto_sign_verify_internal(sig, siglen, m, mlen, pre, 2 + ctxlen, pk);
}


/*************************************************
* Nome:        crypto_sign_open
*
* Descrizione: Verifica un messaggio firmato `sm = sig || msg`.
*              Se la firma è valida, estrae `msg` in output.
*
* Argomenti:
*    - uint8_t *m:         buffer di output per il messaggio estratto
*    - size_t *mlen:       lunghezza del messaggio in output
*    - const uint8_t *sm:  buffer in input contenente [firma || messaggio]
*    - size_t smlen:       lunghezza totale di sm (firma + messaggio)
*    - const uint8_t *ctx: contesto (opzionale)
*    - size_t ctxlen:      lunghezza del contesto
*    - const uint8_t *pk:  chiave pubblica
*
* Ritorna: 0 se la firma è valida, -1 se non è valida
**************************************************/
int crypto_sign_open(uint8_t *m,
                     size_t *mlen,
                     const uint8_t *sm,
                     size_t smlen,
                     const uint8_t *ctx,
                     size_t ctxlen,
                     const uint8_t *pk)
{
  size_t i;

  // Controllo che la firma sia almeno lunga quanto CRYPTO_BYTES
  if(smlen < CRYPTO_BYTES)
    goto badsig;

  // Calcolo lunghezza del messaggio (smlen = sig || msg)
  *mlen = smlen - CRYPTO_BYTES;

  // Verifica la firma: sm[0..CRYPTO_BYTES-1] = sig, sm[CRYPTO_BYTES..] = msg
  if(crypto_sign_verify(sm, CRYPTO_BYTES, sm + CRYPTO_BYTES, *mlen, ctx, ctxlen, pk))
    goto badsig;

  else {
    // Firma valida → copia il messaggio in output
    for(i = 0; i < *mlen; ++i)
      m[i] = sm[CRYPTO_BYTES + i];
    return 0;
  }

badsig:
  // Firma non valida → azzera m, restituisce errore
  *mlen = 0;
  for(i = 0; i < smlen; ++i)
    m[i] = 0;

  return -1;
}

