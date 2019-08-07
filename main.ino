#include <stdio.h>
#include <time.h>
#include "magma.h"
#include "rsa.h"
#include "random.h"

#include <ESP8266WiFi.h>
#include <WiFiClient.h>
#include <ESP8266WebServer.h>

Magma m;
uint32_t* session_key;

void setup(){
  initialize();
  uint32_t* key = (uint32_t*)calloc(8, sizeof(uint32_t));
  for (auto i = -1; ++i < 8; key[i] = random((uint8_t)32));  
  uint64_t sdfrw = (uint64_t) analogRead(A0); //some data from real world
  uint64_t seed = m.crypt(sdfrw, key, true, 8);
  srand(seed);

  session_key = (uint32_t*)calloc(8, sizeof(uint32_t));
  for (auto i = -1; ++i < 8; key[i] = random((uint8_t)32) ^ m.crypt((uint64_t) analogRead(A0), key, true, 8));

  uint64_t* obfuscated_key = (uint64_t*)calloc(8, sizeof(uint64_t));
  uint64_t* encrypted_key = (uint64_t*)calloc(8, sizeof(uint64_t));
  for (auto i = -1; ++i < 8; obfuscated_key[i] = (((uint64_t)random((uint8_t)30) & 0x00FFFFFF) << 32) | session_key[i]);  
  RSA::cipher(obfuscated_key, 8, encrypted_key, 0x2e7e80003e15ULL, 0x1d1a1fad6400e2bULL);
  //here encrypted_key should be sent to server
}

void loop(){
  FILE* data = fopen("data01.txt", "a+");
  //getting any data
  fprintf(data, "param = \"%d\"\n", analogRead(A0));
  fclose(data);

  //if (time_to_send)
  { //here we should check if it is time to send data
    uint32_t* iv = (uint32_t*)calloc(2, sizeof(uint32_t));
    //could be a key, a hash of data or whatever else
    m.gamma("data01.txt", "encrypted", session_key, iv, true);
    //here encrypted file should be sent to server
    FILE* f = fopen("data01.txt", "w");
    //cutting file to zero-length
    fclose(f);
  }
}
