
/*
Name-Abhishek Kumar Yadav
ID-202051004
Section-1
*/



//importing the function
#include<stdio.h>
#include<stdlib.h>
#include <stdint.h>
#include <math.h>


//permutation function to permute the data according to bit wise
uint16_t permutation(uint16_t w){
int permutationbox[] = {0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15};
uint16_t result = 0;
for(int j=0;j<=15;j++){
 //finding the last bit of text w using w%2 operation and then left shifting it by required number using permutation box and storing the final value in result.
result = result | ((w%2) << permutationbox[j]);
w = w/2; //divide by 2 function removes the last bit of text w.
}
return result; //returning the final permutated result
}


//subsitution function 
uint16_t substitution(uint16_t xor_plaintext){
  int s[]={14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7};
  uint16_t m,y,z,w,q;
  
  //using and operation we access the last 4 bits of xor_plaintext
  uint16_t x=xor_plaintext & 0x000f; 
     w=s[x]; //finding the position from subsitution box and storing in w.

     //using and operation we access the last 9th to 12th bits of xor_plaintext
     y=xor_plaintext & 0x00f0;
     y=y>>4; //left shift the y to make the digit occurs at first 4 bits.
      q=s[y];  //finding the position from subsitution box and storing in w.
      w=w | q<<4; //finally XORing the w with left shifted 4 bit q so that it come at last second position.

     //using and operation we access the last 5th to 8th bits of xor_plaintext
     z=xor_plaintext & 0x0f00;
     z=z>>8; //left shift the y to make the digit occurs at first 4 bits.
      q=s[z]; //finding the position from subsitution box and storing in w.
      w=q<<8 | w; //finally XORing the w with left shifted 8 bit q so that it come at last third position.

      m=xor_plaintext & 0xf000;
      m=m>>12;
      q=s[m];
      w=q<<12 | w;

    return w; //finally returning the subsituted ciphertext
}

//Reverse subsitution function used in decrypting the result using sunsituting
uint16_t reverseSubstitution(uint16_t result1){
int rs[]={14,3,4,8,1,12,10,15,7,13,9,6,11,2,0,5};
uint16_t x,w,y,q,z,m;

 x=result1 & 0x000f;
     w=rs[x];

     y=result1 & 0x00f0;
     y=y>>4;
      q=rs[y];
      w=w | q<<4;

     z=result1 & 0x0f00;
     z=z>>8;
      q=rs[z];
      w=q<<8 | w;

      m=result1 & 0xf000;
      m=m>>12;
      q=rs[m];
      w=q<<12 | w;

    return w;  //finally returning the permutated ciphertext
}


//encryption function to encrypt the plaintext
  uint16_t encryption(uint16_t plaintext,uint32_t key){
  uint16_t result = plaintext;


//Round 1 encryption

  uint16_t k1 = key>>16; //shifting the key right by 16bits and storing the result of 32 bits in 16 bit which take the least significant 16 bits
  printf("Round 1 key generation(K1) : %hx\n",k1);
  result = result ^ k1;  //Xor operation of plaintext with key.
  printf("XOR reslut of 1st Round : %hx \n",result);
  result = substitution(result); //subsituting the XOR result using subsitution table.
  printf("1st Subsitution result(S1) : %hx\n",result);
  result = permutation(result);  //permuting the result obtained by subsitution using permutation box given.
  printf("1st Round Encryption result : %hx \n",result);
  printf("\n");


//Round 2 encryption

  k1 = key>>12;
  printf("Round 2 key generation(K2) : %hx\n",k1);
  result = result ^ k1;
  printf("XOR reslut of 2nd Round : %hx \n",result);
  result = substitution(result);
  printf("2nd Subsitution result(S2) : %hx\n",result);
  result = permutation(result);
  printf("2nd Round Encryption result : %hx \n",result);
 printf("\n");

//Round 3 encryption

  k1 = key>>8;
  printf("Round 3 key generation(K3) : %hx\n",k1);
  result = result ^ k1;
  result = substitution(result);
    printf("3rd Subsitution result(S3) : %hx\n",result);
  result = permutation(result);
    printf("3rd Round Encryption result : %hx \n",result);
 printf("\n");

//Round 4 encryption

  k1 = key>>4;
  printf("Round 4 key generation(K4) : %hx\n",k1);
  result = result ^ k1;
    printf("XOR result of 4th Round : %hx \n",result);
  result = substitution(result);
  printf("4th Round Encryption result : %hx \n",result);
 printf("\n");

//Round 5 encryption

  k1 = key;
  printf("Round 5 key generation(K5) : %hx\n",k1);
  result = result ^ k1;
  printf("5th Round Encryption result : %hx \n",result);
 printf("\n");
  
  return result; //finally return the encrypted ciphertext using all round.
 }



uint16_t decryption(uint16_t ciphertext,uint32_t key){
  uint16_t result = ciphertext;

//Round 1 decryption

  uint16_t k1 = key;
  printf("Round 1 key generation(K1) : %hx\n",k1);
  result = result ^ k1;
  printf("1st Round Decryption result : %hx \n",result);
 printf("\n");
  
//Round 2 decryption

  k1 = key>>4;
  printf("Round 2 key generation(K2) : %hx\n",k1);
  result = reverseSubstitution(result);
   printf("2nd ReverseSubsitution result(S2) : %hx\n",result);
  result = result ^ k1;
   printf("2nd Round Decryption result : %hx \n",result);
 printf("\n");
  

  //Round 3 decryption

   k1 = key>>8;
   printf("Round 3 key generation(K3) : %hx\n",k1);
  result = permutation(result);
    printf("3rd Round permutation result : %hx \n",result);
  result = reverseSubstitution(result);
   printf("3rd ReverseSubsitution result(S3) : %hx\n",result);
  result = result ^ k1;
   printf("3rd Round Decryption result : %hx \n",result);
 printf("\n");
 
//Round 4 decryption

  k1 = key>>12;
  printf("Round 4 key generation(K4) : %hx\n",k1);
  result = permutation(result);
  printf("4th Round permutation result : %hx \n",result);
  result = reverseSubstitution(result);
   printf("4th ReverseSubsitution result(S4) : %hx\n",result);
  result = result ^ k1;
   printf("4th Round Decryption result : %hx \n",result);
 printf("\n");
  
//Round 5 decryption

  k1 = key>>16;
  printf("Round 5 key generation(K5) : %hx\n",k1);
  result = permutation(result);
  printf("5th Round permutation result : %hx \n",result);
  result = reverseSubstitution(result);
   printf("5th ReverseSubsitution result(S5) : %hx\n",result);
  result = result ^ k1;
  printf("5th Round Decryption result : %hx \n",result);
 printf("\n");

  return result;
 }


int main(){
    uint16_t plaintext,key,xor_plaintext,ciphertext;
    uint32_t secretkey,temp;
    
    printf("Enter the Plaintext(it should be 16 bit) : ");
    scanf("%hx",&plaintext);
    printf("Enter the Secret key(it should be 32 bit) : ");
    scanf("%x",&secretkey);
    printf("\n");

    ciphertext = encryption(plaintext,secretkey);  //calling the encryption function

    printf("Final encrypted ciphertext : %x\n",ciphertext);  //printing the final encrpted ciphertext from all round

    printf("**************************************************\n");
    printf("Final decrypted plaintext : %x\n",decryption(ciphertext,secretkey)); //decrypting the ciphertext to obtain the given plaintext
    printf("**************************************************\n");

     }

