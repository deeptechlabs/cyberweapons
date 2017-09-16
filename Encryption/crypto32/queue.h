// specification file for an unlimited queue for storing bytes

#ifndef CRYPTOPP_QUEUE_H
#define CRYPTOPP_QUEUE_H

#include "cryptlib.h"

NAMESPACE_BEGIN(CryptoPP)

// The queue is implemented as a linked list of arrays, but you don't need to
// know about that.  So just ignore this next line. :)
class ByteQueueNode;

class ByteQueue : public BufferedTransformation
{
public:
	ByteQueue(unsigned int nodeSize=256);
	ByteQueue(const ByteQueue &copy);
	~ByteQueue();

	// how many bytes currently stored
	unsigned long CurrentSize() const;
	unsigned long MaxRetrieveable()
		{return CurrentSize();}

	void Put(byte inByte);
	void Put(const byte *inString, unsigned int length);

	void Clear();

	// both functions returns the number of bytes actually retrived
	unsigned int Get(byte &outByte);
	unsigned int Get(byte *outString, unsigned int getMax);

	unsigned long TransferTo(BufferedTransformation &target);
	unsigned int TransferTo(BufferedTransformation &target, unsigned int transferMax);

	virtual unsigned int Skip(unsigned int skipMax);

	unsigned int Peek(byte &outByte) const;
	unsigned int Peek(byte *outString, unsigned int peekMax) const;

	unsigned long CopyTo(BufferedTransformation &target) const;
	unsigned int CopyTo(BufferedTransformation &target, unsigned int copyMax) const;

	ByteQueue & operator=(const ByteQueue &rhs);
	bool operator==(const ByteQueue &rhs) const;
	byte operator[](unsigned long i) const;

private:
	void CleanupUsedNodes();
	void CopyFrom(const ByteQueue &copy);
	void Destroy();

	unsigned int nodeSize;
	ByteQueueNode *head, *tail;
};

NAMESPACE_END

#endif
