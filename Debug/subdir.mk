################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../ae_interfaces.c \
../asue_interfaces.c \
../csenn_eXosip2.c \
../interface.c \
../main.c \
../uac.c \
../uas.c 

OBJS += \
./ae_interfaces.o \
./asue_interfaces.o \
./csenn_eXosip2.o \
./interface.o \
./main.o \
./uac.o \
./uas.o 

C_DEPS += \
./ae_interfaces.d \
./asue_interfaces.d \
./csenn_eXosip2.d \
./interface.d \
./main.d \
./uac.d \
./uas.d 


# Each subdirectory must supply rules for building sources it contributes
%.o: ../%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


