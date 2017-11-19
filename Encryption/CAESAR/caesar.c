/* Author: Chris Garry
//
// Description: A Caesar Cipher
// algorithm to encrypt plaintext
// messages over the lowercase a-z alphabet.
//
*/

#include <stdlib.h>
#include <time.h>
#include <stdio.h>
#include <string.h>

#define TRUE 1
#define FALSE 0
#define SIZE_ALPHABET 26

char alphabet[] = {'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q',
                        'r','s','t','u','v','w','x','y','z'};

void gettimeofday();

//Returns a random rotation value from the interval [1,25]
int random_rot(){

    struct timeval start;
    gettimeofday(&start, NULL);

    //Seed the random number generator with seconds*microseconds
    srand(start.tv_usec * start.tv_sec);

    return (rand()%(SIZE_ALPHABET-1) + 1);
}

//Returns TRUE if a string is valid within the alphabet
int str_check(char *string){

    int length = strlen(string);
    int i;
    if(length > 0){
        
        for(i =0; i<length; i++){

            if(string[i]<'a' || string[i]>'z'){
                return FALSE;
            }
        }
        return TRUE;
    }
    return FALSE;
}

//Rotates plaintext characters over the alphabet by rot on interval [-26, 26]
void rot_plaintext(char *plaintext, int rot){

    int x;
    for(x=0; x<strlen(plaintext); x++){
        plaintext[x] = alphabet[(plaintext[x]-'a'+rot+SIZE_ALPHABET) % SIZE_ALPHABET];
    }
}

char *encrypt(char *plaintext, int rot){

    if(str_check(plaintext)==TRUE){
        rot_plaintext(plaintext, rot);
    }
    return plaintext;
}

char *decrypt(char *ciphertext, int rot){
    
    if(str_check(ciphertext)==TRUE){
        rot_plaintext(ciphertext, -rot);
    }
    return ciphertext;
}

//Guess the rot value by brute force
void brute_crack(char *ciphertext){
    int i;
    for(i = 0; i<SIZE_ALPHABET; i++){
        printf("Guess: %s Rot:%d\n", decrypt(ciphertext, i), i);
        decrypt(ciphertext, -i);
    }
}

int main(int argc, char *argv[]){

    char string[] = "apples";
    char *encrypted = encrypt(string, 2);
    brute_crack(encrypted);
    return 0;
}
