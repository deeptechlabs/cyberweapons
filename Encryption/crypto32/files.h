#ifndef CRYPTOPP_FILES_H
#define CRYPTOPP_FILES_H

#include "cryptlib.h"
#include "filters.h"

#include <iostream>
#include <fstream>

NAMESPACE_BEGIN(CryptoPP)

class FileSource : public Source
{
public:
	class Err : public Exception {public: Err(const char *message) : Exception(message) {}};
	class OpenErr : public Err {public: OpenErr(const char *message) : Err(message) {}};
	class ReadErr : public Err {public: ReadErr() : Err("FileSource: error reading file") {}};

	FileSource(std::istream &in, bool pumpAndClose=false,
			   BufferedTransformation *outQueue = NULL);
	FileSource(const char *filename, bool pumpAndClose=false,
			   BufferedTransformation *outQueue = NULL);

	std::istream& GetStream() {return in;}

	unsigned int Pump(unsigned int size);
	unsigned long PumpAll();

private:
	std::ifstream file;
	std::istream& in;
};

class FileSink : public Sink
{
public:
	class Err : public Exception {public: Err(const char *message) : Exception(message) {}};
	class OpenErr : public Err {public: OpenErr(const char *message) : Err(message) {}};
	class WriteErr : public Err {public: WriteErr() : Err("FileSink: error writing file") {}};

	FileSink(std::ostream &out);
	FileSink(const char *filename, bool binary=true);

	std::ostream& GetStream() {return out;}

	void InputFinished();
	void Put(byte inByte)
	{
		out.put(inByte);
		if (!out.good())
		  throw WriteErr();
	}

	void Put(const byte *inString, unsigned int length);

private:
	std::ofstream file;
	std::ostream& out;
};

NAMESPACE_END

#endif
