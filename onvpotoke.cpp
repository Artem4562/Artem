#include <iostream>
#include <thread>
#include <chrono>
#include <conio.h>
using namespace std;

int main() {
    int x=10;
    int y=25;
    int z=x+y;
    cout<<"Sum of x+y = " << z << endl;
    chrono::milliseconds(10000);
    cout << this_thread::get_id() << endl;
    this_thread::sleep_for(chrono::milliseconds(10000));
    cout<<"Sum of x+y = " << z;
    getch();
}