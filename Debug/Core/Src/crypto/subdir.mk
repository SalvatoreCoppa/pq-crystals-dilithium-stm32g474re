################################################################################
# Automatically-generated file. Do not edit!
# Toolchain: GNU Tools for STM32 (13.3.rel1)
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../Core/Src/crypto/fips202.c \
../Core/Src/crypto/ntt.c \
../Core/Src/crypto/packing.c \
../Core/Src/crypto/poly.c \
../Core/Src/crypto/polyvec.c \
../Core/Src/crypto/randombytes.c \
../Core/Src/crypto/reduce.c \
../Core/Src/crypto/rounding.c \
../Core/Src/crypto/sign.c \
../Core/Src/crypto/symmetric-shake.c 

OBJS += \
./Core/Src/crypto/fips202.o \
./Core/Src/crypto/ntt.o \
./Core/Src/crypto/packing.o \
./Core/Src/crypto/poly.o \
./Core/Src/crypto/polyvec.o \
./Core/Src/crypto/randombytes.o \
./Core/Src/crypto/reduce.o \
./Core/Src/crypto/rounding.o \
./Core/Src/crypto/sign.o \
./Core/Src/crypto/symmetric-shake.o 

C_DEPS += \
./Core/Src/crypto/fips202.d \
./Core/Src/crypto/ntt.d \
./Core/Src/crypto/packing.d \
./Core/Src/crypto/poly.d \
./Core/Src/crypto/polyvec.d \
./Core/Src/crypto/randombytes.d \
./Core/Src/crypto/reduce.d \
./Core/Src/crypto/rounding.d \
./Core/Src/crypto/sign.d \
./Core/Src/crypto/symmetric-shake.d 


# Each subdirectory must supply rules for building sources it contributes
Core/Src/crypto/%.o Core/Src/crypto/%.su Core/Src/crypto/%.cyclo: ../Core/Src/crypto/%.c Core/Src/crypto/subdir.mk
	arm-none-eabi-gcc "$<" -mcpu=cortex-m4 -std=gnu11 -g3 -DDEBUG -DUSE_HAL_DRIVER -DSTM32G474xx -c -I../Core/Inc -I../Drivers/STM32G4xx_HAL_Driver/Inc -I../Drivers/STM32G4xx_HAL_Driver/Inc/Legacy -I../Drivers/CMSIS/Device/ST/STM32G4xx/Include -I../Drivers/CMSIS/Include -I../Core/Inc/crypto -O0 -ffunction-sections -fdata-sections -Wall -fstack-usage -fcyclomatic-complexity -MMD -MP -MF"$(@:%.o=%.d)" -MT"$@" --specs=nano.specs -mfpu=fpv4-sp-d16 -mfloat-abi=hard -mthumb -o "$@"

clean: clean-Core-2f-Src-2f-crypto

clean-Core-2f-Src-2f-crypto:
	-$(RM) ./Core/Src/crypto/fips202.cyclo ./Core/Src/crypto/fips202.d ./Core/Src/crypto/fips202.o ./Core/Src/crypto/fips202.su ./Core/Src/crypto/ntt.cyclo ./Core/Src/crypto/ntt.d ./Core/Src/crypto/ntt.o ./Core/Src/crypto/ntt.su ./Core/Src/crypto/packing.cyclo ./Core/Src/crypto/packing.d ./Core/Src/crypto/packing.o ./Core/Src/crypto/packing.su ./Core/Src/crypto/poly.cyclo ./Core/Src/crypto/poly.d ./Core/Src/crypto/poly.o ./Core/Src/crypto/poly.su ./Core/Src/crypto/polyvec.cyclo ./Core/Src/crypto/polyvec.d ./Core/Src/crypto/polyvec.o ./Core/Src/crypto/polyvec.su ./Core/Src/crypto/randombytes.cyclo ./Core/Src/crypto/randombytes.d ./Core/Src/crypto/randombytes.o ./Core/Src/crypto/randombytes.su ./Core/Src/crypto/reduce.cyclo ./Core/Src/crypto/reduce.d ./Core/Src/crypto/reduce.o ./Core/Src/crypto/reduce.su ./Core/Src/crypto/rounding.cyclo ./Core/Src/crypto/rounding.d ./Core/Src/crypto/rounding.o ./Core/Src/crypto/rounding.su ./Core/Src/crypto/sign.cyclo ./Core/Src/crypto/sign.d ./Core/Src/crypto/sign.o ./Core/Src/crypto/sign.su ./Core/Src/crypto/symmetric-shake.cyclo ./Core/Src/crypto/symmetric-shake.d ./Core/Src/crypto/symmetric-shake.o ./Core/Src/crypto/symmetric-shake.su

.PHONY: clean-Core-2f-Src-2f-crypto

