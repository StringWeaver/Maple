#pragma once
#include "pch.h"
#include "unknwnbase.h"
#include "winrt/Windows.Storage.Streams.h"

struct __declspec(uuid("905a0fef-bc53-11df-8c49-001e4fc686da")) IBufferByteAccess : ::IUnknown
{
    virtual HRESULT __stdcall Buffer(uint8_t** value) = 0;
};

