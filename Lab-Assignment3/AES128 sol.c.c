/*

Name-Abhishek Kumar Yadav
Roll-202051004

*/

#include <stdio.h>
#include <stdint.h>

//SubBytes table from which we will pick up the value for subbytes encryption
unsigned char sub[16][16] = {

    {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
    {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
    {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
    {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
    {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
    {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
    {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
    {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
    {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
    {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
    {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
    {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
    {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
    {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
    {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
    {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}};

//Declaration of implicit function so that we may use the function in any order it will not show error

unsigned char Plaintext(unsigned char plaintext[4][4]);
unsigned char Subbytes(unsigned char subbytes_arr[4][4], unsigned char plaintext[4][4]);
unsigned char Shiftrows(unsigned char shiftrow_arr[4][4], unsigned char subbytes_arr[4][4]);
unsigned char Mixcolumn(unsigned char mixcolumn_arr[4][4], unsigned char shiftrow_arr[4][4]);
unsigned char DecShiftrows(unsigned char shiftrow_arr[4][4], unsigned char subbytes_arr[4][4]);
unsigned char DecSubbytes(unsigned char subbytes_arr[4][4], unsigned char plaintext[4][4]);
void Keyscheduling(uint8_t key[16], unsigned char k[11][16]);


//we will pass the input result and n(number of time the loop will run)
//value of n is decided bythe power of x.Suppose x^4 so n=4
unsigned char multiplyByXpower(unsigned char s, int n)

{

    unsigned char t;

    for (int i = 0; i < n; i++)
    {

        t = s << 1;  //left shift input result by 1

        if (s >> 7 == 1)  //checking that if the most significant bit of input result is 1 or not if it is 1 then we will XOR 
                          //with 27 to make in the range of 8 bits that is in power of x^7
        {

            t = t ^ 27;
        }

        s = t;    //storing the result in s so that we may again use the value while calling
    }

    return s;
}

uint8_t subBytes(uint8_t SUBBYTES)

{

    int t1, t2;

    t1 = SUBBYTES & 15; //Suppose SUBBYTES is 53 by doing and(&) operation with 15 it store 3 in t1

    t2 = (SUBBYTES >> 4);  //Suppose SUBBYTES is 53 by shifting 4 position right it store 5 in t2

    return (sub[t2][t1]);  //search the value from the subbytes table where t2 is representing rows and t1 represents column
}

//The SUBWORD function takes a 32-bit word as input and applies the S-Box (substitution box) to each of the 4 bytes of 
//the word independently. The S-Box is a lookup table that maps each possible byte value to a different byte value, based 
//on the algorithm we have used in subbytes function.
uint32_t SUBWORD(uint32_t subt)
{

    return (subBytes(subt >> 24) << 24) | (subBytes((subt & 0x00ff0000) >> 16) << 16) | (subBytes((subt & 0x0000ff00) >> 8) << 8) | (subBytes(subt & 0x000000ff));
}


//The ROTWORD function takes a 32-bit word as input and performs a circular left shift on the 4 bytes of the word. 
//Specifically, the first byte is moved to the end of the word, and the remaining 3 bytes are shifted one position 
//to the left. For example, if we have a word represented as 0x12345678, the ROTWORD function will transform it to 0x23456781. 
uint32_t ROTWORD(uint32_t input)
{

    uint32_t res;

    res = input >> 24;

    input = (input << 8) ^ res;

    return input;
}

//we take the input key from the user
unsigned char KEY(unsigned char tempkey[16])
{

    printf("Enter key of 128bits(16 hexadecimal values):\n");

    for (int i = 0; i < 16; i++)

    {
    scanf("%hhx", &tempkey[i]);
  }

}

//Keycheduling algorithm take 128 bits input and generate a secret key of 128 bit using different function given below
void Keyscheduling(uint8_t key[16], unsigned char k[11][16])
{

    uint32_t Rcon[10];

    uint32_t w[44];

 //Declaraing total 10 Rcon which have fixed value
    Rcon[0] = 0x01000000;

    Rcon[1] = 0x02000000;

    Rcon[2] = 0x04000000;

    Rcon[3] = 0x08000000;

    Rcon[4] = 0x10000000;

    Rcon[5] = 0x20000000;

    Rcon[6] = 0x40000000;

    Rcon[7] = 0x80000000;

    Rcon[8] = 0x1B000000;

    Rcon[9] = 0x36000000;

    //Printing first 3 word which is of 32 bit using the algorithm given below
    for (int i = 0; i <= 3; i++)
    {
        //key is of 8 bit so we take 4 key and shift it in  way to make it of 32 bits by concatinating them(all these make one word of 32 bit)
        w[i] = key[4 * i] << 24 ^ key[4 * i + 1] << 16 ^ key[4 * i + 2] << 8 ^ key[4 * i + 3];

        // printf(" %x\n",w[i]);
    }
   //Printing the next 41 word which is of 32 bit using the algorithm given below
    for (int i = 4; i < 44; i++)
    {

        uint32_t temp = w[i - 1];

        if (i % 4 == 0)
        {
           // passing the temp(32 bit) to ROTWORD(it basically shift bit in a circular way such that MSB 8 
           //bit is placed at LSB 8 bit and rest LSB 24 bit is shifted to MSB 24 bit)
           //the output of ROTWORD is passed into SUBWORD(SUBWORD is basically our normal subbytes function)
            temp = SUBWORD(ROTWORD(temp)) ^ Rcon[(i / 4) - 1];
        }

        w[i] = w[i - 4] ^ temp;
    }
    
    //Our secret key(k) is a 2D matrix of 11 rows and 16 columns.Secret key is of 128 bit so 
    //we break it into 16 hexadecimal 8 bit and store in the columns
    for (int i = 0; i < 11; i++)
    {

        k[i][0] = w[4 * i] >> 24;

        k[i][1] = w[4 * i] >> 16;

        k[i][2] = w[4 * i] >> 8;

        k[i][3] = w[4 * i];

        k[i][4] = w[4 * i + 1] >> 24;

        k[i][5] = w[4 * i + 1] >> 16;

        k[i][6] = w[4 * i + 1] >> 8;

        k[i][7] = w[4 * i + 1];

        k[i][8] = w[4 * i + 2] >> 24;

        k[i][9] = w[4 * i + 2] >> 16;

        k[i][10] = w[4 * i + 2] >> 8;

        k[i][11] = w[4 * i + 2];

        k[i][12] = w[4 * i + 3] >> 24;

        k[i][13] = w[4 * i + 3] >> 16;

        k[i][14] = w[4 * i + 3] >> 8;

        k[i][15] = w[4 * i + 3];
    }

//printing the secret key
printf("\nThe secret key generated is of k[11][16] matrix\n");
    for (int a = 0; a < 11; a++)
    {

        for (int i = 0; i < 16; i++)

        {

            printf(" %hx", k[a][i]);
        }

        printf("\n");
    }
    printf("\n");
}


unsigned char Plaintext(unsigned char text[4][4])
{

    // read plaintext input and store in a 2D 4*4 matrix

    printf("Enter plaintext of 128bits(16 hexadecimal values):\n");

    for (int i = 0; i < 4; i++)

    {

        for (int j = 0; j < 4; j++)

        {

            scanf("%hhx", &text[i][j]);

        }

    }

}


//The SUBWORD function takes a 32-bit word as input and applies the S-Box (substitution box) to each of the 4 bytes of 
//the word independently. The S-Box is a lookup table that maps each possible byte value to a different byte value, based 
//on the algorithm we have used in subbytes function.
unsigned char subbytes(unsigned char SUBBYTES)

{

    SUBBYTES = multiplyByXpower(SUBBYTES, 1) ^ 0x01;

    int t1, t2;

    t1 = SUBBYTES & 15;

    t2 = (SUBBYTES >> 4);

    return (sub[t2][t1]);
}

unsigned char Subbytes(unsigned char subbytes_arr[4][4], unsigned char plaintext[4][4])
{

    //printf("\n");

    // printf("output for subbytes\n");

    for (int i = 0; i < 4; i++)

    {

        for (int j = 0; j < 4; j++)

        {

            subbytes_arr[i][j] = subbytes(plaintext[i][j]); //calling the subbytes function and storing the result in a subbytes_arr

            // printf("%02x ", subbytes_arr[i][j]);
        }
    }
}

unsigned char decsubbytes(unsigned char SUBBYTES)

{

    int i, j;

    unsigned char x;

    for (i = 0; i < 16; i++)

    {

        for (j = 0; j < 16; j++)

        {

            if (sub[i][j] == SUBBYTES)   //check from the S-BOX table and check where SUBBYTES match store the row and column in i and j 
                                         //and shift i and j accordingly to get the output and store in x

            {

                x = i;

                x = (x << 4) | j;

                break;
            }
        }
    }

    SUBBYTES = x;

   //Decsubbytes= inverse(2)*(S^1)
   // inverse(2)=x^7+x^3+x^2+1
   //now we use multiplyByXpower function to calculate the resultant output
    SUBBYTES = multiplyByXpower((SUBBYTES ^ 0x01), 7) ^ multiplyByXpower((SUBBYTES ^ 0x01), 3) ^ multiplyByXpower((SUBBYTES ^ 0x01), 2) ^ SUBBYTES ^ 0x01;

    return SUBBYTES;
}


unsigned char DecSubbytes(unsigned char subbytes_arr[4][4], unsigned char plaintext[4][4])
{

   // printf("\n");

    // printf("output for decsubbytes\n");

    for (int i = 0; i < 4; i++)

    {

        for (int j = 0; j < 4; j++)

        {

            plaintext[i][j] = decsubbytes(subbytes_arr[i][j]);  //calling the decsubbytes function and storing the result in a plaintext

            // printf("%02x ", plaintext[i][j]);
        }
    }
}

unsigned char shiftrows(unsigned char SHIFTROWS[4][4])

{

    //we do not shift the first row 
    //shift the second row by 1 in a left circular way
    int t1 = SHIFTROWS[1][0];

    SHIFTROWS[1][0] = SHIFTROWS[1][1];

    SHIFTROWS[1][1] = SHIFTROWS[1][2];

    SHIFTROWS[1][2] = SHIFTROWS[1][3];

    SHIFTROWS[1][3] = t1;


     //shift the third row by 2 in a left circular way
    int t2 = SHIFTROWS[2][0];

    int t21 = SHIFTROWS[2][1];

    SHIFTROWS[2][0] = SHIFTROWS[2][2];

    SHIFTROWS[2][1] = SHIFTROWS[2][3];

    SHIFTROWS[2][2] = t2;

    SHIFTROWS[2][3] = t21;

   //shift the fourth row by 3 in a left circular way
    int t3 = SHIFTROWS[3][3];

    SHIFTROWS[3][3] = SHIFTROWS[3][2];

    SHIFTROWS[3][2] = SHIFTROWS[3][1];

    SHIFTROWS[3][1] = SHIFTROWS[3][0];

    SHIFTROWS[3][0] = t3;
}


unsigned char Shiftrows(unsigned char shiftrow_arr[4][4], unsigned char subbytes_arr[4][4])
{

    for (int i = 0; i < 4; i++)

    {

        for (int j = 0; j < 4; j++)

        {

            shiftrow_arr[i][j] = subbytes_arr[i][j]; //storing the result of subbytes_arr array in shiftrow_arr array
        }
    }

    shiftrows(shiftrow_arr);  //calling the shiftrows function

   // printf("\n");

    // printf("output for shiftrow\n");

    for (int i = 0; i < 4; i++)

    {

        for (int j = 0; j < 4; j++)

        {

            // printf("%02x ", shiftrow_arr[i][j]);
        }
    }
}

unsigned char Revshiftrows(unsigned char SHIFTROWS[4][4])

{
     //we do not shift the first row 
    //shift the second row by 1 in a right circular way
    int t1 = SHIFTROWS[1][3];

    SHIFTROWS[1][3] = SHIFTROWS[1][2];

    SHIFTROWS[1][2] = SHIFTROWS[1][1];

    SHIFTROWS[1][1] = SHIFTROWS[1][0];

    SHIFTROWS[1][0] = t1;

    //shift the third row by 2 in a right circular way

    int t2 = SHIFTROWS[2][3];

    int t21 = SHIFTROWS[2][2];

    SHIFTROWS[2][3] = SHIFTROWS[2][1];

    SHIFTROWS[2][2] = SHIFTROWS[2][0];

    SHIFTROWS[2][1] = t2;

    SHIFTROWS[2][0] = t21;

     //shift the fourth row by 3 in a right circular way

    int t3 = SHIFTROWS[3][0];

    SHIFTROWS[3][0] = SHIFTROWS[3][1];

    SHIFTROWS[3][1] = SHIFTROWS[3][2];

    SHIFTROWS[3][2] = SHIFTROWS[3][3];

    SHIFTROWS[3][3] = t3;
}

unsigned char DecShiftrows(unsigned char shiftrow_arr[4][4], unsigned char subbytes_arr[4][4])
{

    for (int i = 0; i < 4; i++)

    {

        for (int j = 0; j < 4; j++)

        {

            subbytes_arr[i][j] = shiftrow_arr[i][j];  //storing the shiftrow_arr value to subbytes_arr array
        }
    }

    Revshiftrows(subbytes_arr);   //calling the Revshiftrows function

   // printf("\n");

    // printf("output for Revshiftrow\n");

    for (int i = 0; i < 4; i++)

    {

        for (int j = 0; j < 4; j++)

        {

            // printf("%02x ", subbytes_arr[i][j]);
        }
    }
}



unsigned char Mixcolumn(unsigned char mixcolumn_arr[4][4], unsigned char shiftrow_arr[4][4])
{

    for (int i = 0; i < 4; i++)

    {

        for (int j = 0; j < 4; j++)

        {
             // we will call the multiplyByXpower function and perform the operation shown below
             // 1*shiftrow_arr[j][i]|shiftrow_arr[(j + 1) % 4][i]*x^2 | shiftrow_arr[(j + 2) % 4][i]*x^2| shiftrow_arr[(j + 3) % 4][i]+ 1*shiftrow_arr[(j + 3) % 4][i]
            mixcolumn_arr[j][i] = shiftrow_arr[j][i] ^ multiplyByXpower(shiftrow_arr[(j + 1) % 4][i], 2) ^ multiplyByXpower(shiftrow_arr[(j + 2) % 4][i], 2) 
                                  ^ multiplyByXpower(shiftrow_arr[(j + 3) % 4][i], 2) ^ shiftrow_arr[(j + 3) % 4][i];
        }
    }

    //printf("\n");

    // printf("output for mixcolumn\n");

    for (int i = 0; i < 4; i++)

    {

        for (int j = 0; j < 4; j++)

        {

            // printf("%hx ", mixcolumn_arr[i][j]);
        }
    }
}

unsigned char DecMixcolumn(unsigned char mixcolumn_arr[4][4], unsigned char shiftrow_arr[4][4])
{

    for (int i = 0; i < 4; i++)

    {

        for (int j = 0; j < 4; j++)

        {
            //165=10100101=x^7 + x^5 + x^2 + 1
            //7  =00000111=x^2 + x + 1
            //26 =00011010=x^4 + x^3 + x
            //115=01110011=x^6 + x^5 + x^4 + x + 1
            //now we will call the multiplyByXpower function and do the following operation accordingly
            shiftrow_arr[j][i] = multiplyByXpower(mixcolumn_arr[j][i], 7) ^ multiplyByXpower(mixcolumn_arr[j][i], 5) ^ multiplyByXpower(mixcolumn_arr[j][i], 2) ^ mixcolumn_arr[j][i]

                                 ^ multiplyByXpower(mixcolumn_arr[(j + 1) % 4][i], 2) ^ multiplyByXpower(mixcolumn_arr[(j + 1) % 4][i], 1) ^ mixcolumn_arr[(j + 1) % 4][i]

                                 ^ multiplyByXpower(mixcolumn_arr[(j + 2) % 4][i], 4) ^ multiplyByXpower(mixcolumn_arr[(j + 2) % 4][i], 3) ^ multiplyByXpower(mixcolumn_arr[(j + 2) % 4][i], 1)

                                 ^ multiplyByXpower(mixcolumn_arr[(j + 3) % 4][i], 6) ^ multiplyByXpower(mixcolumn_arr[(j + 3) % 4][i], 5) ^ multiplyByXpower(mixcolumn_arr[(j + 3) % 4][i], 4)

                                 ^ multiplyByXpower(mixcolumn_arr[(j + 3) % 4][i], 1) ^ mixcolumn_arr[(j + 3) % 4][i];
        }
    }

    printf("\n");

    // printf("Decrypt output for mixcolumn\n");

    for (int i = 0; i < 4; i++)

    {

        for (int j = 0; j < 4; j++)

        {

            // printf("%hx ", shiftrow_arr[i][j]);
        }
    }
}



//we will take plaintext and key as input and perform the xor operation
void xor (unsigned char table[4][4], unsigned char key[16]) {
    int a = 0;

    for (int i = 0; i < 4; i++)

    {

        for (int j = 0; j < 4; j++)

        {
            // XOR is performed by taking the plaintext column wise and key as row wise
            table[i][j] = table[i][j] ^ key[a];

            a++;
        }
    }
}


//main function 

    int main()

    {

    unsigned char plaintext[4][4];
    unsigned char key[16];
    unsigned char subbytes_arr[4][4];
    unsigned char shiftrow_arr[4][4];
    unsigned char mixcolumn_arr[4][4];
    unsigned char k[11][16];
    unsigned char text[4][4];
    unsigned char tempkey[16];
    
    printf("Name-Abhishek Kumar Yadav\n");
    printf("Roll-202051004\n\n");

    // calling the function Plaintext and storing the result of text array to plaintext array
     Plaintext(text);
    // printf("the text us \n");
     for(int i=0;i<4;i++){
        for(int j=0;j<4;j++){
            plaintext[i][j]=text[i][j];
           // printf("%hx ",plaintext[i][j]);
        }
     }
     printf("\n");

     //calling the function KEY and storing the result of tempkey array to key array
     KEY(tempkey);
     //printf("the key u\n");
     for(int i=0;i<16;i++){
        key[i]=tempkey[i];
        //printf("%hx ",key[i]);
     }
     
     //keyscheduling function takes the key given by user and convert it into the secret key and store it in 'k' arrray
     Keyscheduling(key, k);

   
    //performing encryption for 9 rounds
    printf("\n");
    for (int i = 0; i < 9; i++)

    {

        xor(plaintext, k[i]);

        Subbytes(subbytes_arr, plaintext);

        Shiftrows(shiftrow_arr, subbytes_arr);

        Mixcolumn(mixcolumn_arr, shiftrow_arr);

        printf("Round %d encryption text is \n", i + 1);

        for (int x = 0; x < 4; x++)
        {

            for (int y = 0; y < 4; y++)
            {
                //finally storing the mixcolumn_arr value to plaintext array so that we may use it as input plaintext for next round
                plaintext[x][y] = mixcolumn_arr[x][y];
            }
        }

        for (int x = 0; x < 4; x++)
        {

            for (int y = 0; y < 4; y++)
            {

                printf(" %hhx", plaintext[x][y]);
            }
        }

        printf("\n\n");
    }
    //printf("\n");

    xor(plaintext, k[9]);

    Subbytes(subbytes_arr, plaintext);

    Shiftrows(shiftrow_arr, subbytes_arr);
    printf("Round 10 encryption text is \n");
    for (int x = 0; x < 4; x++)
    {

        for (int y = 0; y < 4; y++)
        {

            plaintext[x][y] = shiftrow_arr[x][y];
        }
    }
    for (int x = 0; x < 4; x++)
    {

        for (int y = 0; y < 4; y++)
        {

            printf("%hhx ",plaintext[x][y]);
        }
    }

    xor(plaintext, k[10]);
    printf("\n");

    printf("\n***************Final Cipher text generated is ***********************\n\n");

    for (int x = 0; x < 4; x++)
    {

        for (int y = 0; y < 4; y++)
        {

            printf(" %hhx", plaintext[x][y]);
        }
    }

    printf("\n\n****************************************************************************\n\n");
    printf("Round 10 decryption \n");
    xor(plaintext, k[10]);
    for (int x = 0; x < 4; x++)
    {

        for (int y = 0; y < 4; y++)
        {

             printf(" %hhx ", plaintext[x][y]);
        }
    }

    printf("\n");
    for (int x = 0; x < 4; x++)
    {

        for (int y = 0; y < 4; y++)
        {

            subbytes_arr[x][y] = plaintext[x][y];
        }
    }
    DecShiftrows(subbytes_arr, shiftrow_arr);
    DecSubbytes(shiftrow_arr, subbytes_arr);

    for (int x = 0; x < 4; x++)
    {

        for (int y = 0; y < 4; y++)
        {

            plaintext[x][y] = subbytes_arr[x][y];
        }
    }
    printf("\n");
    xor(plaintext, k[9]);
    printf("round 9 decryption \n");
     for (int x = 0; x < 4; x++)
    {

        for (int y = 0; y < 4; y++)
        {

            printf("%hhx ",plaintext[x][y]);
            
        }
    }
    //xor(plaintext, k[9]);
     //printf("round 9 decryption \n");
    // for (int x = 0; x < 4; x++)
    // {

    //     for (int y = 0; y < 4; y++)
    //     {

    //         printf(" %hhx ", plaintext[x][y]);
    //     }
    // }

     printf("\n");
    for (int i = 8; i >= 0; i--)

    {
        for (int x = 0; x < 4; x++)
        {

            for (int y = 0; y < 4; y++)
            {

                mixcolumn_arr[x][y] = plaintext[x][y];
            }
        }
        DecMixcolumn(mixcolumn_arr, shiftrow_arr);
        DecShiftrows(shiftrow_arr, subbytes_arr);
        DecSubbytes(subbytes_arr, plaintext);
        xor(plaintext, k[i]);

        printf("Round %d decryption is \n", i);

        for (int x = 0; x < 4; x++)
        {

            for (int y = 0; y < 4; y++)
            {

                printf(" %hhx", plaintext[x][y]);
            }
        }

        printf("\n");
    }
   
    printf("\n**************************Final Decrypted ciphertext is *************************\n\n");
    for (int x = 0; x < 4; x++)
        {

            for (int y = 0; y < 4; y++)
            {

                printf(" %hhx", plaintext[x][y]);
            }
        }
      printf("\n\n*********************************************************************************\n");

    return 0;
}































