/*
 * @Coding: UTF-8
 * @Author: Ziyi Dong
 * @Created: 05-14-2025
 * @Last Modified: 05-27-2025
 * @Copyright: © 2025 Ziyi Dong. All rights reserved.
 * @License: GPLv3.0
 * @Contact: ziyidong.cs@gmail.com
 */

#include <stdio.h>
#include <iostream>
#include <string.h>

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
#include "bendmarking.h"
#include "cpamaptozr.h"
#include "ccamain.h"
#include "pbc.h"
#include "robust_receiver_test.h"
#include "robust_trade_test.h"

using namespace std;

#define ROBUST_TEST_RECEIVER_NUMBER_100 100
#define ROBUST_TEST_RECEIVER_NUMBER_300 300
#define ROBUST_TEST_RECEIVER_NUMBER_500 500
#define ROBUST_TEST_RECEIVER_NUMBER_1000 1000
#define ROBUST_TEST_RECEIVER_NUMBER_3000 3000
#define ROBUST_TEST_RECEIVER_NUMBER_5000 5000
#define ROBUST_TEST_RECEIVER_NUMBER_10000 100000

#define ROBUST_TEST_TREADE_NUMBER_10 10
#define ROBUST_TEST_TREADE_NUMBER_30 30
#define ROBUST_TEST_TREADE_NUMBER_50 50
#define ROBUST_TEST_TREADE_NUMBER_100 100

int main()
{

    // CPA Scheme Test
    int cpatest;
    cpatest = cpamain();
    if (cpatest){
        cout << "[PASS] CPA Scheme Test completed successfully." << endl;
    }
    else{
        cout << "[FAIL] CPA Scheme Test failed." << endl;
    }

    // CCA Scheme Test
    int ccatest;
    ccatest = ccamain();
    if (ccatest){
        cout << "[PASS] CCA Scheme Test completed successfully." << endl;
    }
    else{
        cout << "[FAIL] CCA Scheme Test failed." << endl;
    }

    // Bendmarking Scheme Test
    int bendmarking_result;
    bendmarking_result = bendmarking();
    if (bendmarking_result){
        cout << "[PASS] BendTest Scheme Test completed successfully." << endl;
    }
    else{
        cout << "[FAIL] BendTest Scheme Test failed." << endl;
    }

    // Robust Receiver Test
    FILE *robust_receiver_file;
    robust_receiver_file = fopen("robust_receiver_test.txt", "w");
    if (robust_receiver_file == NULL) {
        perror("[Fail] Unable to open robust_receiver_test.txt.");
        exit(1);
    }
    fprintf(robust_receiver_file, "=== Robust Receiver Test Start ===\n");
    fclose(robust_receiver_file);

    robustReceiverTest(ROBUST_TEST_RECEIVER_NUMBER_100);
    printf("Robustness test with 100 receivers completed.\n");

    robustReceiverTest(ROBUST_TEST_RECEIVER_NUMBER_300);
    printf("Robustness test with 300 receivers completed.\n");

    robustReceiverTest(ROBUST_TEST_RECEIVER_NUMBER_500);
    printf("Robustness test with 500 receivers completed.\n");

    robustReceiverTest(ROBUST_TEST_RECEIVER_NUMBER_1000);
    printf("Robustness test with 1000 receivers completed.\n");

    robustReceiverTest(ROBUST_TEST_RECEIVER_NUMBER_3000);
    printf("Robustness test with 3000 receivers completed.\n");

    robustReceiverTest(ROBUST_TEST_RECEIVER_NUMBER_5000);
    printf("Robustness test with 5000 receivers completed.\n");

    robustReceiverTest(ROBUST_TEST_RECEIVER_NUMBER_10000);
    printf("Robustness test with 10000 receivers completed.\n");

    robust_receiver_file = fopen("robust_receiver_test.txt", "a");
    if (robust_receiver_file == NULL) {
        perror("[Fail] Unable to open robust_receiver_test.txt.");
        exit(1);
    }
    fprintf(robust_receiver_file, "=== Robust Receiver Test End ===\n");
    fclose(robust_receiver_file);

    // Robust Trade Test

    FILE *robust_trade_file;
    robust_trade_file = fopen("robust_trade_test.txt", "w");
    if (robust_trade_file == NULL) {
        perror("[Fail] Unable to open robust_trade_test.txt.");
        exit(1);
    }
    fprintf(robust_trade_file, "=== Robust Trade Test Start ===\n");
    fclose(robust_trade_file);

    robustTradeTest(ROBUST_TEST_TREADE_NUMBER_10, ROBUST_TEST_RECEIVER_NUMBER_100);
    printf("Robustness test with 10 trade, 100 receivers completed.\n");

    robustTradeTest(ROBUST_TEST_TREADE_NUMBER_30, ROBUST_TEST_RECEIVER_NUMBER_100);
    printf("Robustness test with 30 trade, 100 receivers completed.\n");

    robustTradeTest(ROBUST_TEST_TREADE_NUMBER_50, ROBUST_TEST_RECEIVER_NUMBER_100);
    printf("Robustness test with 50 trade, 100 receivers completed.\n");

    robustTradeTest(ROBUST_TEST_TREADE_NUMBER_100, ROBUST_TEST_RECEIVER_NUMBER_100);
    printf("Robustness test with 100 trade, 100 receivers completed.\n");

    robust_trade_file = fopen("robust_trade_test.txt", "a");
    if (robust_trade_file == NULL) {
        perror("[Fail] Unable to open robust_trade_test.txt.");
        exit(1);
    }
    fprintf(robust_trade_file, "=== Robust Trade Test End ===\n");
    fclose(robust_trade_file);

    printf("=== All Tests Completed ===\n");

    return 0;

}