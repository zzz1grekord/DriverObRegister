#pragma once

#include <iostream>
#include <Windows.h>

namespace Console
{
	enum colors
	{
		black = 0,
		blue,
		green,
		cyan,
		red,
		magenta,
		brown,
		lightgray,
		darkgray,
		lightblue,
		lightgreen,
		lightcyan,
		lightred,
		lightmagenta,
		yellow,
		white
	};

	void SetColor( colors code );

	std::ostream& GreenText( const char* text );

	std::ostream& Information( const char* text );
	std::ostream& Warning( const char* text );
	std::ostream& Error( const char* text );
	std::ostream& Success( const char* text );
}