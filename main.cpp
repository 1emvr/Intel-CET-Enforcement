#include <windows.h>
#include <cstdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <matteo.cpp>

class Base {
};

class Derived : public Base {
public:
  virtual void test1();
};

int main(void) {

  // obj_buffer, 1st vfgadget, api, args

  Target target; 
  uint8_t hijack[8];
  uint8_t vfgadget0[8];
  uint8_t winapi[8];

  /*
	void _fastcall Target::trigger(Target *this, char *args1)

	mov [rsp+0x10], rdx ; move string arugment 0x10 above the stack (shadow)
	mov [rsp+0x8], rcx ; move this_ptr 0x8 above the stack  (shadow)
	sub rsp, 0x38

	mov rax, [rsp+0x38+0x8] ; move this_ptr (shadow) to rax
	mov rax, [rax+0x8] ; move vf_1 to rax 
	mov [rsp+0x38-0x18], rax ; move vf_1 to 3rd position from top of stack (?)

	mov rax, [rsp+0x38+0x8] ; move this_ptr (shadow) to rax
	mov rcx, [rax+0x8] ; move vf_1 to rcx
	mov rax, [rsp+0x38-0x18] ; restore saved vf_1 pointer to rax

	call cs:__guard_dispatch_icall_fptr ; check CFG/CET for vf_1
	add rsp, 0x38 ; rax is never called
	ret
   */

}
