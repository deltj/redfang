OBJ=fang.o
EXE=fang

DEPS=

LIBS=-lbluetooth -lpthread
CCFLAGS=-Wall -Werror

all: release

release: $(OBJ) $(DEPS)
	$(CC) $(CCFLAGS) -O2 -o $(EXE) $(OBJ) $(LIBS)

debug: $(OBJ) $(DEPS)
	$(CC) $(CCFLAGS) -O0 -g -DDEBUG -o $(EXE) $(OBJ) $(LIBS)

clean:
	rm -f $(EXE) $(OBJ) *~
