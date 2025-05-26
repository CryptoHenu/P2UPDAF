/*
 * @Coding: UTF-8
 * @Author: Ziyi Dong
 * @Created: 05-14-2025
 * @Last Modified: 05-24-2025
 * @Copyright: © 2025 Ziyi Dong. All rights reserved.
 * @License: GPL v3.0
 * @Contact: dongziyics@gmail.com
 */

#include "ccamain.h"
#include <stdio.h>
#include <iostream>
#include <string.h>
#include "pbc.h"
#include "cpastruct.h"
#include "cpakeygen.h"
#include "cpadec.h"
#include "cpaenc.h"
#include "cpamaptozr.h"
#include "cpamain.h"
#include "ccastruct.h"
#include "ccakeygen.h"
#include "ccadec.h"
#include "ccaenc.h"
#include "ccamap.h"
#include "ccamain.h"
#include "bendmarkingmain.h"
#include "robustnesstest.h"
#include "cpamaptozr.h"

using namespace std;


int main()
{
    //CPA scheme test
    // int cpatest;
    // cpatest = cpamain();
    // if (cpatest){
    //     cout << "CPA scheme test is successful !" << endl;
    // }
    // else{
    //     cout << "CPA scheme test is false !" << endl;
    // }

    // CCA scheme test
    int ccatest;
    ccatest = ccamain();
    if (ccatest){
        cout << "CCA scheme test is successful !" << endl;
    }
    else{
        cout << "CCA scheme test is false !" << endl;
    }

    // // Bendmarking scheme test
    // int bendtest;
    // bendtest = bendmain();
    // if (bendtest){
    //     cout << "[PASS] BendTest Scheme Test completed successfully." << endl;
    // }
    // else{
    //     cout << "[FAIL] BendTest Scheme Test failed." << endl;
    // }

    // Bendmarking scheme test
    // int robustnesstest;
    // robustnesstest = robustnesstestmain();
    // if (robustnesstest){
    //     cout << "bendtest scheme test is successful !" << endl;
    // }
    // else{
    //     cout << "bendtest scheme test is false !" << endl;
    // }

    return 0;

}