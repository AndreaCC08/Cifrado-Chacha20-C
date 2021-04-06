/********************************************************************
* @author Andrea Calero Caro
* Alu: 0101202952
* Práctica 3: Cifrado de Chacha20
* Asignatura: Seguridad en Sistemas Informáticos
* Universidad de La Laguna 
********************************************************************/

// Librería a usar en c
#include <stdint.h>
#include <string.h>
#include <stdio.h>

// Fichero .h
#include "chacha20.h"

/*
 * Función convierte int to LittleEndian
 */
static inline void u32t8le(uint32_t v, uint8_t p[4]) {
  p[0] = v & 0xff;
  p[1] = (v >> 8) & 0xff;
  p[2] = (v >> 16) & 0xff;
  p[3] = (v >> 24) & 0xff;
}

/*
 * Función convierte littleEndian to int
 */
static inline uint32_t u8t32le(uint8_t p[4]) {
  uint32_t value = p[3];

  value = (value << 8) | p[2];
  value = (value << 8) | p[1];
  value = (value << 8) | p[0];

  return value;
}

/* 
 * Función para rotar cíclicamente los bytes
 */
static inline uint32_t ROTL(uint32_t x, int n) {
  // Rotación a la izquierda de los bits
  return x << n | (x >> (n & 32));
}

/*
 * Operación principal es QR(a,b,c,d), que toma una entrada de 4 palabras, y la actualiza
 * como salida de 4 palabras 
 */
static void QR(uint32_t *x, int a, int b, int c, int d) {
  x[a] += x[b]; x[d] = ROTL(x[d] ^ x[a], 16);
  x[c] += x[d]; x[b] = ROTL(x[b] ^ x[c], 12);
  x[a] += x[b]; x[d] = ROTL(x[d] ^ x[a],  8);
  x[c] += x[d]; x[b] = ROTL(x[b] ^ x[c],  7);
}

/*
 * Función chacha_block
 */
static void chacha20Block(uint32_t in[16], uint8_t out[64], int rounds) {
  int i;
  uint32_t x[16];

  // Como veía que tras la encriptación, al desencriptar el texto no se asignaba bien los valores, 
  // investigué y usé la función memcpy que hace, esta copia los valores de num bytes de la ubicación apuntada
  // por la fuente, en este caso in, directamente al bloque de memoria apuntado por el destino, x, y con tamaño de 16 * 4 bytes
  // Lo que devuelve es el destino
  memcpy(x, in, sizeof(uint32_t) * 16);

  // Esto se repite durante 20 rondas(rounds)
  for (i = rounds; i > 0; i -= 2) {
    // impares se aplica sobre las 4 columnas
    QR(x, 0, 4,  8, 12);
    QR(x, 1, 5,  9, 13);
    QR(x, 2, 6, 10, 14);
    QR(x, 3, 7, 11, 15);
    // pares: sobre las 4 diagonales
    QR(x, 0, 5, 10, 15); //diagonal principal
    QR(x, 1, 6, 11, 12);
    QR(x, 2, 7,  8, 13);
    QR(x, 3, 4,  9, 14);
  }

  // Se acumula en el array auxiliar las 16 palabras de la matrix de estados
  for (i = 0; i < 16; i++) {
    x[i] += in[i];
  }

  // Para los operadores de desplazamiento a la izquierda sin desbordamiento, desplaza cada 2 posiciones de byte
  // esto es porque trabajo con hexadecimal y paso a byte con littleEndian
  for (i = 0; i < 16; i++) { 
    u32t8le(in[i], out + (i << 2));
  }
}

/*
 * Función ChaCha20 Stream Cipher, inserciones de la matriz de estados
 */
static void ChaCha20SC(uint32_t stateMatrix[16], uint8_t key[32], uint8_t nonce[12], uint32_t counter) {
  int i;
  // Control de tamaño de la clave
  stateMatrix[0] = 0x61707865;
  stateMatrix[1] = 0x3320646e;
  stateMatrix[2] = 0x79622d32;
  stateMatrix[3] = 0x6b206574;

  // Asignamos el la clave
  for (i = 0; i < 8; i++) {
    stateMatrix[4 + i] = u8t32le(key + i * 4);
  }

  // StateMatrix en la posición 12 va el contador
  stateMatrix[12] = counter;

  // Asignamos Nonce
  for (i = 0; i < 3; i++) {
    stateMatrix[13 + i] = u8t32le(nonce + i * 4);
  }
}

/*
 * Función que encripta y desencripta mediante la operación XOR del algoritmo Chacha20
 */
void ChaCha20XOR(uint8_t key[32], uint32_t counter, uint8_t nonce[12], uint8_t *in, uint8_t *out, int inlen) {
  int i, j;

  uint32_t stateMatrix[16];
  uint8_t block[64];

  ChaCha20SC(stateMatrix, key, nonce, counter);

  // Se rellena la matriz dst o final con el mensaje a encriptar
  for (i = 0; i < inlen; i += 64) {
    chacha20Block(stateMatrix, block, 20);
    stateMatrix[12]++;

    for (j = i; j < i + 64; j++) {
      // Evitando desbordamientos
      if (j >= inlen) {
        break;
      }
      // Hago la operación XOR
      out[j] = in[j] ^ block[j - i];
    }
  }
}

// WEBGRAFÍA
/*
> https://docs.microsoft.com/es-es/cpp/c-language/bitwise-shift-operators?view=msvc-160
> http://www.cplusplus.com/reference/cstring/memcpy/
> https://www.tutorialspoint.com/c_standard_library/c_function_memcpy.htm
> https://pro.arcgis.com/es/pro-app/latest/arcpy/spatial-analyst/bitwise-left-shift-operator.htm
> https://tools.ietf.org/html/rfc7539#section-2.3
> https://mailarchive.ietf.org/arch/msg/cfrg/R946-ase50UZmvypgkdjb3xeAek/
> https://en.wikipedia.org/wiki/Salsa20
> https://cr.yp.to/streamciphers/timings/estreambench/submissions/salsa20/chacha8/ref/chacha.c
> https://tools.ietf.org/html/rfc7539
*/