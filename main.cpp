#include <stdio.h>
#include <string.h>

#include "pbc.h"

int main()
{
    pairing_t pairing;   // 定义配对对象
    element_t generator; // 定义生成元元素

    // 1. 初始化配对参数（使用预定义的 Type A 参数）
    const char *param_str =
        "type a\n"
        "q 8780710799663312522437781984754049815806883199414208211022683396663570522207602206790247281104613111\n"
        "h 120160122648911460793888213667405342048029544012513118202832259291762929507923\n"
        "r 730750818665451621361119245571504901405976559617\n"
        "exp2 159\n"
        "exp1 107\n"
        "sign1 1\n"
        "sign0 1\n";

    pairing_init_set_buf(pairing, param_str, strlen(param_str)); // 从字符串加载参数[6]

    // 2. 生成椭圆曲线生成元（G1群的基点）
    element_init_G1(generator, pairing); // 初始化G1群元素

    element_random(generator); // 随机生成G1群的生成元[3,11]

    // 3. 打印生成元坐标
    printf("生成元坐标:\n");
    element_printf("X = %B\n", generator); // 输出生成元的x,y坐标[6,11]

    // 4. 清理内存
    element_clear(generator);

    pairing_clear(pairing);

    return 0;
}