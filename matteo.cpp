#include <stdio.h>
#include <string.h>
#include <stdlib.h>

class Target {
public:
  char *args = nullptr;
  int (*callback)(char *args) = nullptr;

  virtual void trigger(char *args1) {
	callback(args);
  }
}
