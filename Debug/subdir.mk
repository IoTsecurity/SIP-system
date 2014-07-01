################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../dispatch.c \
../interface.c \
../main.c \
../sip_com.c \
../sm1.c \
../uac.c \
../uas.c 

OBJS += \
./dispatch.o \
./interface.o \
./main.o \
./sip_com.o \
./sm1.o \
./uac.o \
./uas.o 

C_DEPS += \
./dispatch.d \
./interface.d \
./main.d \
./sip_com.d \
./sm1.d \
./uac.d \
./uas.d 


# Each subdirectory must supply rules for building sources it contributes
%.o: ../%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -I/usr/local/openssl/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


