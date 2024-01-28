//ТЗ: сделать прогу.


#include <iostream>
#include <thread>
#include <chrono>
#include <conio.h>
using namespace std;

void sum(int &a, int &b){
    this_thread::sleep_for(chrono::milliseconds(5000));
    a+=b;
    cout<< "sum is done" << endl;
    cout<<"x = " << a << " " <<"y = " << b << endl;
}


void multiplication(int &a, int &b){
    this_thread::sleep_for(chrono::milliseconds(5000));
    a*=b;
    cout<< "mult is done" << endl;
    cout<<"x = " << a << " " <<"y = " << b << endl;
}

void sumM(int* A){
    this_thread::sleep_for(chrono::milliseconds(5000));
    for (int i=0; i<4; ++i){
        A[i]+=1;
    }
    cout<< "sumM is done" << endl <<"A = ";
    for (int i=0; i<4; ++i){
        cout<< A[i];
    }
    cout<< endl;
}


int main() {
    int X[5] {0,1,2,3,4};



    // int x=10;
    // int y=25;
    // cout<<"x = " << x << " " <<"y = " << y << endl;
    // thread t(sum, ref(x), ref(y));
    // thread h(multiplication, ref(x), ref(y));
    // // cout << this_thread::get_id() << endl;
    // t.join();
    // h.join();
    // getch();
}