// -*- coding: utf-8 -*-

/*
 *
 *Author:  Ziyi Dong
 *
*/ 

#include <stdio.h>
#include <iostream>
#include <string.h>

#include "pbc.h"
#include "struct.h"
#include "keygen.h"
#include "cpadec.h"
#include "cpaenc.h"
#include "maptozr.h"
#include "cpamain.h"

using namespace std;



int main()
{
    // CPA scheme test
    int cpatest;
    cpatest = cpamain();
    if (cpatest){
        cout << "CPA scheme test is successful !" << endl;
    }
    else{
        cout << "CPA scheme test is false !" << endl;
    }


    return 0;
}