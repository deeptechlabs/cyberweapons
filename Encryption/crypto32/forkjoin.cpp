// forkjoin.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "forkjoin.h"
#include "queue.h"
#include <memory>

NAMESPACE_BEGIN(CryptoPP)

Fork::Fork(unsigned int n, BufferedTransformation *const *givenOutPorts)
	: numberOfPorts(n), outPorts(n)
{
	currentPort = 0;

	for (unsigned int i=0; i<numberOfPorts; i++)
		outPorts[i].reset(givenOutPorts ? givenOutPorts[i] : new ByteQueue);
}

Fork::Fork(BufferedTransformation *outport0, BufferedTransformation *outport1)
	: numberOfPorts(2), outPorts(2)
{
	currentPort = 0;
	outPorts[0].reset(outport0 ? outport0 : new ByteQueue);
	outPorts[1].reset(outport1 ? outport1 : new ByteQueue);
}

void Fork::SelectOutPort(unsigned int portNumber)
{
	currentPort = portNumber;
}

void Fork::Detach(BufferedTransformation *newOut)
{
	std::auto_ptr<BufferedTransformation> out(newOut ? newOut : new ByteQueue);
	outPorts[currentPort]->Close();
	outPorts[currentPort]->TransferTo(*out);
	outPorts[currentPort].reset(out.release());
}

void Fork::Attach(BufferedTransformation *newOut)
{
	if (outPorts[currentPort]->Attachable())
		outPorts[currentPort]->Attach(newOut);
	else
		Detach(newOut);
}

void Fork::Close()
{
	InputFinished();

	for (unsigned int i=0; i<numberOfPorts; i++)
		outPorts[i]->Close();
}

void Fork::Put(byte inByte)
{
	for (unsigned int i=0; i<numberOfPorts; i++)
		outPorts[i]->Put(inByte);
}

void Fork::Put(const byte *inString, unsigned int length)
{
	for (unsigned int i=0; i<numberOfPorts; i++)
		outPorts[i]->Put(inString, length);
}

// ********************************************************

Join::Join(unsigned int n, BufferedTransformation *outQ)
	: Filter(outQ),
	  numberOfPorts(n),
	  inPorts(n),
	  interfacesOpen(n),
	  interfaces(n)
{
	for (unsigned int i=0; i<numberOfPorts; i++)
	{
		inPorts[i].reset(new ByteQueue);
		interfaces[i].reset(new JoinInterface(*this, *inPorts[i], i));
	}
}

JoinInterface * Join::ReleaseInterface(unsigned int i)
{
	return interfaces[i].release();
}

void Join::NotifyInput(unsigned int i, unsigned int /* length */)
{
	AccessPort(i).TransferTo(*AttachedTransformation());
}

void Join::NotifyClose(unsigned int /* id */)
{
	if ((--interfacesOpen) == 0)
		AttachedTransformation()->Close();
}

// ********************************************************

void JoinInterface::Put(byte inByte)
{
	bq.Put(inByte);
	parent.NotifyInput(id, 1);
}

void JoinInterface::Put(const byte *inString, unsigned int length)
{
	bq.Put(inString, length);
	parent.NotifyInput(id, length);
}

unsigned long JoinInterface::MaxRetrieveable() 
{
	return parent.MaxRetrieveable();
}

void JoinInterface::Close() 
{
	parent.NotifyClose(id);
}

void JoinInterface::Detach(BufferedTransformation *bt) 
{
	parent.Detach(bt);
}

void JoinInterface::Attach(BufferedTransformation *bt) 
{
	parent.Attach(bt);
}

unsigned int JoinInterface::Get(byte &outByte) 
{
	return parent.Get(outByte);
}

unsigned int JoinInterface::Get(byte *outString, unsigned int getMax)
{
	return parent.Get(outString, getMax);
}

unsigned int JoinInterface::Peek(byte &outByte) const
{
	return parent.Peek(outByte);
}

unsigned int JoinInterface::Peek(byte *outString, unsigned int peekMax) const
{
	return parent.Peek(outString, peekMax);
}

unsigned long JoinInterface::CopyTo(BufferedTransformation &target) const
{
	return parent.CopyTo(target);
}

unsigned int JoinInterface::CopyTo(BufferedTransformation &target, unsigned int copyMax) const
{
	return parent.CopyTo(target, copyMax);
}

NAMESPACE_END
