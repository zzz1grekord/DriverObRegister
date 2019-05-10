#include "Console.hpp"

namespace Console
{
	void SetColor( colors code )
	{
		HANDLE hstdout = GetStdHandle( STD_OUTPUT_HANDLE );
		CONSOLE_SCREEN_BUFFER_INFO csbi;

		if ( !GetConsoleScreenBufferInfo( hstdout, &csbi ) )
			return;

		WORD color = ( csbi.wAttributes & 0xF0 ) + ( code & 0x0F );
		SetConsoleTextAttribute( hstdout, color );

		return;
	}

	std::ostream& GreenText( const char* text )
	{
		SetColor( lightgreen );
		std::cout << text;
		SetColor( lightgray );

		return std::cout;
	}

	std::ostream& Information( const char* text )
	{
		SetColor( colors::lightcyan );
		std::cout << "[INFORMATION] ";
		SetColor( colors::lightgray );
		std::cout << text;

		return std::cout;
	}

	std::ostream& Warning( const char* text )
	{
		SetColor( colors::yellow );
		std::cout << "[WARNING] ";
		SetColor( colors::lightgray );
		std::cout << text;

		return std::cout;
	}

	std::ostream& Error( const char* text )
	{
		SetColor( colors::lightred );
		std::cout << "[ERROR] ";
		SetColor( colors::lightgray );
		std::cout << text;

		return std::cout;
	}

	std::ostream& Success( const char* text )
	{
		SetColor( colors::lightgreen );
		std::cout << "[SUCCESS] ";
		SetColor( colors::lightgray );
		std::cout << text;

		return std::cout;
	}
}