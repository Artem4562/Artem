#include <stdio.h>
#include <conio.h>
#include <iostream>



int main(){
    int i= 0;
    char c =26;
    char a = 64, b=00; //
    for(i=1;i<14;i++){
        std::cout<<i<<std::endl;
    }
    std::cout<<i<<std::endl;
    unsigned int *p= (unsigned int*)((a<<8) | (b));
    printf("Hello, world!");
    //sm::lbr::printSomething();
    printf("%d, %c ",c,c);
    std::cout<<i<<"  "<<&i<<"  "<<p;
    printf("%d",0b11111111111111011000000010010000);
    getch();
    return 0;
}