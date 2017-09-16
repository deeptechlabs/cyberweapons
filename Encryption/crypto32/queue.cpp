// queue.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "queue.h"
#include "misc.h"

NAMESPACE_BEGIN(CryptoPP)

// this class for use by ByteQueue only
class ByteQueueNode
{
public:
	ByteQueueNode(unsigned int maxSize)
		: buf(maxSize)
	{
		head = tail = 0;
		next = 0;
	}

	inline unsigned int CurrentSize() const
	{
		return tail-head;
	}

	inline bool UsedUp() const
	{
		return (head==MaxSize());
	}

	inline void Clear()
	{
		head = tail = 0;
	}

	inline unsigned int Put(byte inByte)
	{
		if (MaxSize()==tail)
			return 0;

		buf[tail++]=inByte;
		return 1;
	}

	inline unsigned int Put(const byte *inString, unsigned int length)
	{
		unsigned int l = STDMIN(length, MaxSize()-tail);
		memcpy(buf+tail, inString, l);
		tail += l;
		return l;
	}

	inline unsigned int Peek(byte &outByte) const
	{
		if (tail==head)
			return 0;

		outByte=buf[head];
		return 1;
	}

	inline unsigned int Peek(byte *target, unsigned int copyMax) const
	{
		unsigned int len = STDMIN(copyMax, tail-head);
		memcpy(target, buf+head, len);
		return len;
	}

	inline unsigned int CopyTo(BufferedTransformation &target) const
	{
		unsigned int len = tail-head;
		target.Put(buf+head, len);
		return len;
	}

	inline unsigned int CopyTo(BufferedTransformation &target, unsigned int copyMax) const
	{
		unsigned int len = STDMIN(copyMax, tail-head);
		target.Put(buf+head, len);
		return len;
	}

	inline unsigned int Get(byte &outByte)
	{
		unsigned int len = Peek(outByte);
		head += len;
		return len;
	}

	inline unsigned int Get(byte *outString, unsigned int getMax)
	{
		unsigned int len = Peek(outString, getMax);
		head += len;
		return len;
	}

	inline unsigned int TransferTo(BufferedTransformation &target)
	{
		unsigned int len = CopyTo(target);
		head += len;
		return len;
	}

	inline unsigned int TransferTo(BufferedTransformation &target, unsigned int transferMax)
	{
		unsigned int len = CopyTo(target, transferMax);
		head += len;
		return len;
	}

	inline unsigned int Skip(unsigned int skipMax)
	{
		unsigned int len = STDMIN(skipMax, tail-head);
		head += len;
		return len;
	}

	inline byte operator[](unsigned int i) const
	{
		return buf[i-head];
	}

	ByteQueueNode *next;

private:
	inline unsigned int MaxSize() const {return buf.size;}

	SecByteBlock buf;
	unsigned int head, tail;
};

// ********************************************************

ByteQueue::ByteQueue(unsigned int nodeSize)
	: nodeSize(nodeSize)
{
	head = tail = new ByteQueueNode(nodeSize);
}

ByteQueue::ByteQueue(const ByteQueue &copy)
{
	CopyFrom(copy);
}

void ByteQueue::CopyFrom(const ByteQueue &copy)
{
	nodeSize = copy.nodeSize;
	head = tail = new ByteQueueNode(*copy.head);

	for (ByteQueueNode *current=copy.head->next; current; current=current->next)
	{
		tail->next = new ByteQueueNode(*current);
		tail = tail->next;
	}

	tail->next = NULL;
}

ByteQueue::~ByteQueue()
{
	Destroy();
}

void ByteQueue::Destroy()
{
	ByteQueueNode *next;

	for (ByteQueueNode *current=head; current; current=next)
	{
		next=current->next;
		delete current;
	}
}

unsigned long ByteQueue::CurrentSize() const
{
	unsigned long size=0;

	for (ByteQueueNode *current=head; current; current=current->next)
		size += current->CurrentSize();

	return size;
}

void ByteQueue::Clear()
{
	Destroy();
	head = tail = new ByteQueueNode(nodeSize);
}

void ByteQueue::Put(byte inByte)
{
	if (!tail->Put(inByte))
	{
		tail->next = new ByteQueueNode(nodeSize);
		tail = tail->next;
		tail->Put(inByte);
	}
}

void ByteQueue::Put(const byte *inString, unsigned int length)
{
	unsigned int l;

	while ((l=tail->Put(inString, length)) < length)
	{
		tail->next = new ByteQueueNode(nodeSize);
		tail = tail->next;
		inString += l;
		length -= l;
	}
}

void ByteQueue::CleanupUsedNodes()
{
	while (head != tail && head->UsedUp())
	{
		ByteQueueNode *temp=head;
		head=head->next;
		delete temp;
	}

	if (head->CurrentSize() == 0)
		head->Clear();
}

unsigned int ByteQueue::Get(byte &outByte)
{
	int l = head->Get(outByte);
	CleanupUsedNodes();
	return l;
}

unsigned int ByteQueue::Get(byte *outString, unsigned int getMax)
{
	unsigned int bytesLeft = getMax;
	for (ByteQueueNode *current=head; bytesLeft && current; current=current->next)
	{
		unsigned int len = current->Get(outString, bytesLeft);
		bytesLeft -= len;
		outString += len;
	}
	CleanupUsedNodes();
	return getMax - bytesLeft;
}

unsigned long ByteQueue::TransferTo(BufferedTransformation &target)
{
	unsigned long len = 0;
	for (ByteQueueNode *current=head; current; current=current->next)
		len += current->TransferTo(target);
	CleanupUsedNodes();
	return len;
}

unsigned int ByteQueue::TransferTo(BufferedTransformation &target, unsigned int transferMax)
{
	unsigned int bytesLeft = transferMax;
	for (ByteQueueNode *current=head; bytesLeft && current; current=current->next)
		bytesLeft -= current->TransferTo(target, bytesLeft);
	CleanupUsedNodes();
	return transferMax - bytesLeft;
}

unsigned int ByteQueue::Skip(unsigned int skipMax)
{
	unsigned int bytesLeft = skipMax;
	for (ByteQueueNode *current=head; bytesLeft && current; current=current->next)
		bytesLeft -= current->Skip(bytesLeft);
	CleanupUsedNodes();
	return skipMax - bytesLeft;
}

unsigned int ByteQueue::Peek(byte &outByte) const
{
	return head->Peek(outByte);
}

unsigned int ByteQueue::Peek(byte *outString, unsigned int peekMax) const
{
	unsigned int bytesLeft = peekMax;
	for (ByteQueueNode *current=head; bytesLeft && current; current=current->next)
	{
		unsigned int len = current->Peek(outString, bytesLeft);
		bytesLeft -= len;
		outString += len;
	}
	return peekMax - bytesLeft;
}

unsigned long ByteQueue::CopyTo(BufferedTransformation &target) const
{
	unsigned long len = 0;
	for (ByteQueueNode *current=head; current; current=current->next)
		len += current->CopyTo(target);
	return len;
}

unsigned int ByteQueue::CopyTo(BufferedTransformation &target, unsigned int copyMax) const
{
	unsigned int bytesLeft = copyMax;
	for (ByteQueueNode *current=head; bytesLeft && current; current=current->next)
		bytesLeft -= current->CopyTo(target, bytesLeft);
	return copyMax - bytesLeft;
}

ByteQueue & ByteQueue::operator=(const ByteQueue &rhs)
{
	Destroy();
	CopyFrom(rhs);
	return *this;
}

bool ByteQueue::operator==(const ByteQueue &rhs) const
{
	const unsigned long currentSize = CurrentSize();

	if (currentSize != rhs.CurrentSize())
		return false;

	for (unsigned long i = 0; i<currentSize; i++)
		if ((*this)[i] != rhs[i])
			return false;

	return true;
}

byte ByteQueue::operator[](unsigned long i) const
{
	for (ByteQueueNode *current=head; current; current=current->next)
	{
		if (i < current->CurrentSize())
			return (*current)[i];
		
		i -= current->CurrentSize();
	}

	// i should be less than CurrentSize(), therefore we should not be here
	assert(false);
	return 0;
}

NAMESPACE_END
