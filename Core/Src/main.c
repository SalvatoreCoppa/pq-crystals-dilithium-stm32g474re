/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.c
  * @brief          : Reference Firmware for Post-Quantum Cryptography Evaluation
  * @target         : ARM Cortex-M4 (STM32G4) @ 16 MHz (HSI)
  * @algorithm      : ML-DSA-44 (CRYSTALS-Dilithium2) Signature Scheme
  * @author			: Salvatore Coppa
  ******************************************************************************
  */
/* USER CODE END Header */

/* Includes ------------------------------------------------------------------*/
#include "main.h"
#include "usart.h"
#include "rng.h"
#include "gpio.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include "api.h"
#include "sign.h"
#include <string.h> // Required for memory block operations (memcpy, memcmp)
#include <stdio.h>  // Required for standard I/O formatting (printf, fflush)

extern UART_HandleTypeDef hlpuart1;
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */

/* --- FAULT INJECTION / ATTACK SIMULATION CONFIGURATION --- */
// Uncomment the following directive to simulate an adversarial ciphertext/message corruption:
#define SIMULATE_MESSAGE_CORRUPTION

/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
/* USER CODE BEGIN PV */

/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
/* USER CODE BEGIN PFP */
void dilithium_test(void);
void hexdump(const char *label, const uint8_t *data, size_t len);
/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */

/**
 * @brief  Retargets standard C library I/O (printf) to the LPUART1 interface.
 * @param  ch: Character to be transmitted
 * @retval Transmitted character
 */
int __io_putchar(int ch)
{
    HAL_UART_Transmit(&hlpuart1, (uint8_t *)&ch, 1, HAL_MAX_DELAY);
    return ch;
}

/**
 * @brief  Transmits a formatted hexadecimal diagnostic dump over serial console.
 * @param  label: ASCII descriptive identifier
 * @param  data: Pointer to the memory buffer to be inspected
 * @param  len: Size of the memory buffer in bytes
 */
void hexdump(const char *label, const uint8_t *data, size_t len)
{
    printf("%s (%lu bytes): ", label, (unsigned long)len);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
    printf("\r\n");
}

/**
 * @brief  Executes functional verification and benchmark of ML-DSA-44 (Dilithium2).
 *         Performs keypair generation, signing, and verification routines.
 */
void dilithium_test(void)
{
    /* Static memory allocation is employed for large cryptographic buffers to prevent
       stack overflow exceptions on embedded Cortex-M4 architectures with constrained RAM. */
    static uint8_t pk[pqcrystals_dilithium2_PUBLICKEYBYTES];
    static uint8_t sk[pqcrystals_dilithium2_SECRETKEYBYTES];
    static uint8_t sm[4096];
    static uint8_t recovered[4096];

    // Target payload definition
    const uint8_t msg[] = "test message";
    uint8_t original[sizeof(msg)];
    memcpy(original, msg, sizeof(msg));

    // Domain separation context (Empty string per baseline PQC specifications)
    const uint8_t ctx[] = "";
    size_t ctxlen = 0;

    size_t smlen;
    size_t rlen;

    // Clear serial terminal screen and initialize diagnostic output
    fflush(stdout);
    printf("\033[2J\033[H");
    printf("\r\n--- CRYSTALS-Dilithium2 (ML-DSA-44) Functional Verification ---\r\n");

    hexdump("Target Payload", msg, sizeof(msg));
    printf("ASCII String: \"%s\"\r\n\n", msg);

    // 1. KEYPAIR GENERATION ROUTINE
    printf("-- Executing Keypair Generation (crypto_sign_keypair)... --\r\n");
    crypto_sign_keypair(pk, sk);

    hexdump("Public Key  (pk)", pk, pqcrystals_dilithium2_PUBLICKEYBYTES);
    hexdump("Secret Key  (sk)", sk, pqcrystals_dilithium2_SECRETKEYBYTES);
    printf("\n");

    // 2. SIGNATURE GENERATION ROUTINE
    printf("-- Executing Signature Generation (crypto_sign)... --\r\n");
    crypto_sign(sm, &smlen, msg, sizeof(msg), ctx, ctxlen, sk);
    printf("  -> Total Signed Message Length: %lu bytes\r\n", (unsigned long)smlen);
    hexdump("Signed Message (sm)", sm, smlen);
    printf("\n");

#if defined(SIMULATE_MESSAGE_CORRUPTION)
    /* Simulate a fault injection or tampering attack by inverting all bits of the
       first payload byte appended immediately after the Dilithium signature block. */
    printf("-- Simulating Adversarial Message Corruption Attack... --\r\n");
    if (smlen > pqcrystals_dilithium2_BYTES) {
        sm[pqcrystals_dilithium2_BYTES + 0] ^= 0xFF;
    }
    printf("\n");
#endif

    // 3. SIGNATURE VERIFICATION ROUTINE
    printf("-- Executing Signature Verification (crypto_sign_open)... --\r\n");
    int valid = crypto_sign_open(recovered, &rlen, sm, smlen, ctx, ctxlen, pk);
    printf("  -> Recovered Payload Length: %lu bytes\r\n", (unsigned long)rlen);

    hexdump("Recovered Payload", recovered, rlen);
    hexdump("Original Payload ", original, sizeof(original));

    if (valid == 0) {
        if (memcmp(original, recovered, sizeof(original)) == 0) {
            printf("  -> Payload Integrity: MATCH (0 bit errors detected).\r\n");
        } else {
            printf("  -> Payload Integrity: MISMATCH (Data corruption detected).\r\n");
        }
    } else {
        printf("  -> Cryptographic Verification Failed: crypto_sign_open returned error code %d\r\n", valid);
    }

    printf("\n=============================================================\n");
    if (valid == 0 && rlen == sizeof(original) && memcmp(original, recovered, sizeof(original)) == 0) {
        printf("\r>>> SUCCESS: SIGNATURE VALIDATED AND ACCEPTED <<<\r\n");
    } else {
        printf("\r>>> REJECTED: SIGNATURE INVALID OR PAYLOAD CORRUPTED <<<\r\n");
    }
    printf("=============================================================\n");
}

/* USER CODE END 0 */

/**
  * @brief  Main application entry point.
  * @retval int
  */
int main(void)
{
  /* USER CODE BEGIN 1 */

  /* USER CODE END 1 */

  /* MCU Configuration--------------------------------------------------------*/
  HAL_Init();

  /* USER CODE BEGIN Init */

  /* USER CODE END Init */

  /* Configure system clock to 16 MHz (HSI) */
  SystemClock_Config();

  /* USER CODE BEGIN SysInit */

  /* USER CODE END SysInit */

  /* Initialize configured peripherals */
  MX_GPIO_Init();
  MX_LPUART1_UART_Init();
  MX_RNG_Init();

  /* USER CODE BEGIN 2 */
  dilithium_test();
  /* USER CODE END 2 */

  /* Infinite loop */
  /* USER CODE BEGIN WHILE */
  while (1)
  {
    /* USER CODE END WHILE */

    /* USER CODE BEGIN 3 */
  }
  /* USER CODE END 3 */
}

/**
  * @brief System Clock Configuration
  * @retval None
  */
void SystemClock_Config(void)
{
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

  /** Configure the main internal regulator output voltage
  */
  HAL_PWREx_ControlVoltageScaling(PWR_REGULATOR_VOLTAGE_SCALE1);

  /** Initialize RCC Oscillators (HSI @ 16MHz, HSI48 for RNG)
  */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSI|RCC_OSCILLATORTYPE_HSI48;
  RCC_OscInitStruct.HSIState = RCC_HSI_ON;
  RCC_OscInitStruct.HSICalibrationValue = RCC_HSICALIBRATION_DEFAULT;
  RCC_OscInitStruct.HSI48State = RCC_HSI48_ON;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_NONE;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    Error_Handler();
  }

  /** Initialize CPU, AHB, and APB bus clocks (No prescalers -> HCLK = 16MHz)
  */
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                              |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_HSI;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV1;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_0) != HAL_OK)
  {
    Error_Handler();
  }
}

/* USER CODE BEGIN 4 */

/* USER CODE END 4 */

/**
  * @brief  This function is executed in case of error occurrence.
  * @retval None
  */
void Error_Handler(void)
{
  /* USER CODE BEGIN Error_Handler_Debug */
  __disable_irq();
  while (1)
  {
  }
  /* USER CODE END Error_Handler_Debug */
}

#ifdef USE_FULL_ASSERT
/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{
  /* USER CODE BEGIN 6 */
  /* Custom implementation for reporting HAL assert errors */
  /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */
