/********************************************************************
* @author Andrea Calero Caro
* Alu: 0101202952
* Práctica 3: Cifrado de Chacha20
* Asignatura: Seguridad en Sistemas Informáticos
* Universidad de La Laguna 
********************************************************************/

#pragma once
#include <stdint.h>

/*
 * Función ChaCha20XOR que encripta y desencripta el mensaje
 */
void ChaCha20XOR(uint8_t key[32], uint32_t counter, uint8_t nonce[12], uint8_t *input, uint8_t *output, int inputlen);
