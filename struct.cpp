#include <iostream>
#include <conio.h>
using namespace std;
struct decoder 
    {
        int age;
        string name;
    };

int main(){
    decoder Misha;
    Misha.age = 20;
    Misha.name ="Миша";
    cout<<"Name:"<<Misha.name<<" "<< "Age:"<<Misha.age<< endl;
    getch();
}