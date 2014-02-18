################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../csenn_eXosip2.c \
../dispatch.c \
../interface.c \
../main.c \
../uac.c \
../uas.c 

OBJS += \
./csenn_eXosip2.o \
./dispatch.o \
./interface.o \
./main.o \
./uac.o \
./uas.o 

C_DEPS += \
./csenn_eXosip2.d \
./dispatch.d \
./interface.d \
./main.d \
./uac.d \
./uas.d 


# Each subdirectory must supply rules for building sources it contributes
%.o: ../%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -I/usr/local/openssl/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


