#设置cmake版本
cmake_minimum_required(VERSION 3.22)

#项目名字
project(PbcBendmarkingCmake)

#设置编译版本
set(CMAKE_CXX_STANDARD 20)

#声明头文件路径
set(INC_DIR ${CMAKE_SOURCE_DIR}/include)
#声明链接库路径
set(LINK_DIR ${CMAKE_SOURCE_DIR}/lib)


#编译文件
add_executable(PbcBendmarkingCmake
        main.cpp
        cpakeygen.cpp
        cpadec.cpp
        cpaenc.cpp
        cpamaptozr.cpp
        cpamain.cpp
)

# 添加头文件搜索路径
target_include_directories(PbcBendmarkingCmake PRIVATE ${INC_DIR})
# 添加库文件搜索路径
target_link_directories(PbcBendmarkingCmake PRIVATE ${LINK_DIR})


# 链接库
target_link_libraries(PbcBendmarkingCmake PRIVATE
        libpbc.a
        libgmp.a
        libssl.a
        libcrypto.a
)

#生成调试信息
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")