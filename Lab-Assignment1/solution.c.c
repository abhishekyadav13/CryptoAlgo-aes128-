#include <stdio.h>
#include<string.h>
void search(char first,char second, int arr[],char km[5][5]){

for(int i=0;i<5;i++){
for(int j=0;j<5;j++){

if(first==km[i][j]){
arr[0]=i;
arr[1]=j;
}
if(second==km[i][j]){
arr[2]=i;
arr[3]=j;
}
}
}
}

void playfairEncryption(char cipher1[],char str[],char km[5][5],int n){

for(int i=0;i<n;i=i+2){
int arr[4];
char first=str[i];
char second=str[i+1];
search(first,second,arr,km);


if(arr[0]==arr[2]){
cipher1[i]=km[arr[0]][(arr[1]+1)%5];
cipher1[i+1]=km[arr[2]][(arr[3]+1)%5];
}
else if(arr[1]==arr[3]){
cipher1[i]=km[(arr[0]+1)%5][arr[1]];
cipher1[i+1]=km[(arr[2]+1)%5][arr[3]];
}
else{
cipher1[i]=km[arr[0]][arr[3]];
cipher1[i+1]=km[arr[2]][arr[1]];
}


}

}

void playfairDecryption(char decrypt1[],char str[],char km[5][5],int n){

for(int i=0;i<n;i=i+2){
int arr[4];
char first=str[i];
char second=str[i+1];
search(first,second,arr,km);


if(arr[0]==arr[2]){
decrypt1[i]=km[arr[0]][(arr[1]+5-1)%5];
decrypt1[i+1]=km[arr[2]][(arr[3]+5-1)%5];
}
else if(arr[1]==arr[3]){
decrypt1[i]=km[(arr[0]+5-1)%5][arr[1]];
decrypt1[i+1]=km[(arr[2]+5-1)%5][arr[3]];
}
else{
decrypt1[i]=km[arr[0]][arr[3]];
decrypt1[i+1]=km[arr[2]][arr[1]];
}


}

}




void encrypt(char cipher2[],char plain[],int l,int a, int b){
for(int i=0;i<l;i++){
cipher2[i]=(a*(plain[i]-'a') + b)%26 + 'a';
}
}


void decrypt(char cipher[],int l,int a_inverse, int b){
for(int i=0;i<l;i++){
cipher[i]=(((cipher[i]-'a') - b + 26)*a_inverse)%26 + 'a';
}
}

int calculateInverse(int a,int m){
for(int i=1;i<m;i++){
if((a*i)%m==1)
return i;
}
return -1;
}


int calculateGCD(int x , int y){
if(x==0)
return y;

return calculateGCD(y%x,x);
}
void generateKeyMatrix(char KeyMatrix[5][5], char *SecretKey){
    //remove duplicates and convert J to I
    int alp[26]={0};//it is basically to insure the repeated char not to be include(0: not included, 1: already taken)
    char matr[25];//before inserting all the unique char to matrix, we have stored the order of all unique char in the array.
    int j=0;//pointer of matr

    //insert all the unique char of secret key
    for(int i=0; i<strlen(SecretKey); i++){
        if(SecretKey[i]=='j'){
            SecretKey[i] = 'i';
        }
        if(alp[SecretKey[i]-'a']==0){
            matr[j] = SecretKey[i];
            alp[SecretKey[i]-'a'] = 1;
            j++;
        }
    }
    //all remainig char of alphabets will be inserted
    for(int i=0; i<26; i++){
        if(i+'a'=='j') continue;
        if(alp[i]==0){
            matr[j] = (char)i+'a';
            j++;
        }
    }

    //print Key MATRIX
    //printf("\n");
    int k=0;
    for(int i=0; i<5; i++){
        for(int j=0; j<5; j++){
            KeyMatrix[i][j] = matr[k];
            //printf("%c  ", KeyMatrix[i][j]);
            k++;
        }
        //printf("\n");
    }
}





int main(){
int n;
printf("Enter the length of plain text : ");
scanf("%d",&n);
char str0[n+1];
printf("Enter plain text : ");

scanf("%s",str0);
char str[30];
int i=1,j=0; 
    //seperate the consecutive repeated char by add X
    str[0]  = str0[0] == 'j'?'i':str0[0];
    while(i<strlen(str0)){
        if(str0[i] == 'j'){
            str0[i] = 'i';
        }
        if(str[j]==str0[i]) {
            j = j+1;
            str[j] = 'x';
            j++;
            str[j] = str0[i];
            i++;
        }
        else{
            j++;
            str[j] = str0[i];
            i++; 
        }
    }
    j++;
    if(j%2!=0){
        str[j] = 'x';
        j++;
    }
    char str3[j+1];
    for(int x=0; x<j; x++){
        str3[x]=str[x];
    }

if(n%2!=0){
str[n]='x';
n=n+1;
}

printf("Delta : ");
for(int i=0;i<n;i++){
printf("%c",str3[i]);
}
printf("\n");


int k1;
printf("Enter the length of key of playfair cipher : ");
scanf("%d",&k1);
printf("Enter first Key (key 1) : ");
char key1[k1];
//for(int i=0;i<k1;i++){
scanf("%s",key1);
//}
printf("%s",key1);
for(int i=0;i<k1;i++){
if(key1[i]=='j'){
key1[i]='i';
}
}

int flag[26];
int k=0,q=0;
char temp='a';
char km[5][5];
generateKeyMatrix(km,key1);
// for(int i=0;i<5;i++){
// for(int j=0;j<5;j++){

// if(k>=k1){
// while(flag[temp-'a']!=0 || temp=='j'){
// temp=temp+1;
// }
// km[i][j]=temp;
// temp++;
// }
// else {
// while(flag[key1[k]-'a']!=0){
// k++;
// }
// if(k>=k1){
// j--;
// continue;
// }
// km[i][j]=key1[k];
// flag[key1[k]-'a']++;
// }
// k++;
// }
// }

printf("Key Matrix of Playfair Cipher : \n");
for(int i=0;i<5;i++){
for(int j=0;j<5;j++){
printf("%c ",km[i][j]);
}
printf("\n");
}

char cipher1[n];
playfairEncryption(cipher1,str3,km,n);

printf("Cipher Text of Playfair Cipher : ");
for(int i=0;i<n;i++){
printf("%c",cipher1[i]);
}
printf("\n");

printf("------------------------------------------------\n");

int a=11,b=15;

int a_inverse;

if(calculateGCD(a,26)!=1){
printf("Invalid Input 'a'\n");
return -1;
}

a_inverse=calculateInverse(a,26);

char cipher2[n];


encrypt(cipher2,cipher1,n,a,b);

printf("Cipher Text of Affine Cipher : ");
for(int i=0;i<n;i++){
printf("%c",cipher2[i]);
}
printf("\n");

//decrypt(cipher2,length,a_inverse,b);
//printf("Decrypted Text : %s\n",cipher2);


printf("----------------------------------------\n");
getchar();
printf("Enter the key for Shift Cipher (small letter only) : ");
char key3;
scanf(" %c",&key3);

char cipher3[n];

for(int i=0;i<n;i++){
cipher3[i]=((cipher2[i]-'a')+(key3-'a'))%26 + 'a';
}

printf("\n--------------------------------------------\n");
printf("Cipher Text of Shift Cipher : ");
for(int i=0;i<n;i++){
printf("%c",cipher3[i]);
}
printf("\n");

char decrypted3[n];

for(int i=0;i<n;i++){
decrypted3[i]=((cipher3[i]-'a') + 26 - (key3-'a'))%26 + 'a';
}
printf("Decrypted Text of Shift Cipher : ");
for(int i=0;i<n;i++){
printf("%c",decrypted3[i]);
}
printf("\n");

printf("--------------------------------------------\n");
decrypt(decrypted3,n,a_inverse,b);
printf("Decrypted Text of Affine Cipher : ");
for(int i=0;i<n;i++){
printf("%c",decrypted3[i]);
}
printf("\n");

printf("--------------------------------------------\n");

char finaldecryption[n];
playfairDecryption(finaldecryption,decrypted3,km,n);
printf("Final Decrypted Text of Playfair Cipher : ");
for(int i=0;i<n;i++){
printf("%c",finaldecryption[i]);
}
printf("\n");

return 0;


}
