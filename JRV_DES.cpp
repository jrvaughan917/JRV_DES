/*
James Vaughan
Professor Shengli Yuan
CS 3326 Network Security
13 October 2014

JRV_DES.cpp

Purposes:
Implement DES in C++
Encryption Input: 8 byte hex as the plaintext, one 7-byte hex as the key (or 8-byte if you ignore the last bit of each byte)
Encryption Output: 8 bytes hex
Decryption Input: 8 bytes hex as the cipher text, one 7-byte hex as the key (or 8-byte if you ignore the last bit of each byte)
Decryption Output: 8 byte hex characters
You must submit your source code, screen shot with "AABBCCDD11223344" as the plain text and "71322185720000" as the key. You will also need to do a demo.

Stages:
1. Initial permutation
2. Key generation
4. Mangler function
5. Round completion (16 rounds)
6. Final permutation
*/


#include "stdafx.h"
#include <fstream>
#include <iostream>
#include <string>
#include <time.h>
#include <math.h>

using namespace std;
using std::string;

std::string FinalTextPermutation(string);
std::string ManglerXOR(string, string);
std::string ManglerFinalPermute(string);
std::string SBOX_A(string);
std::string SBOX_B(string);
std::string SBOX_C(string);
std::string SBOX_D(string);
std::string SBOX_E(string);
std::string SBOX_F(string);
std::string SBOX_G(string);
std::string SBOX_H(string);
std::string BitExpansion(string);
std::string Mangler(string, string);
std::string Final_Key_Left_Permutation(string);
std::string Final_Key_Right_Permutation(string);
std::string RotateTwo(string);
std::string RotateOne(string);
std::string DES_Initial_Permutation_Left(string);
std::string DES_Initial_Permutation_Right(string);
std::string HexToBinary(string);
std::string KeyToBinary(string);
std::string InitialTextPermutation(string);
std::string DES_Encrypt(string, string);
std::string DES_Decrypt(string, string);
void EndOfProgram();
void InvalidResponseGiven();
bool IsValidText(string);


std::string FinalTextPermutation(string TextToPermutate)
{
	string PermutatedText = TextToPermutate;

	// 1
	PermutatedText[1 - 1] = TextToPermutate[40 - 1];
	PermutatedText[2 - 1] = TextToPermutate[8 - 1];
	PermutatedText[3 - 1] = TextToPermutate[48 - 1];
	PermutatedText[4 - 1] = TextToPermutate[16 - 1];
	PermutatedText[5 - 1] = TextToPermutate[56 - 1];
	PermutatedText[6 - 1] = TextToPermutate[24 - 1];
	PermutatedText[7 - 1] = TextToPermutate[64 - 1];
	PermutatedText[8 - 1] = TextToPermutate[32 - 1];

	//2
	PermutatedText[9 - 1] = TextToPermutate[39 - 1];
	PermutatedText[10 - 1] = TextToPermutate[7 - 1];
	PermutatedText[11 - 1] = TextToPermutate[47 - 1];
	PermutatedText[12 - 1] = TextToPermutate[15 - 1];
	PermutatedText[13 - 1] = TextToPermutate[55 - 1];
	PermutatedText[14 - 1] = TextToPermutate[23 - 1];
	PermutatedText[15 - 1] = TextToPermutate[63 - 1];
	PermutatedText[16 - 1] = TextToPermutate[31 - 1];

	//3
	PermutatedText[17 - 1] = TextToPermutate[38 - 1];
	PermutatedText[18 - 1] = TextToPermutate[6 - 1];
	PermutatedText[19 - 1] = TextToPermutate[46 - 1];
	PermutatedText[20 - 1] = TextToPermutate[14 - 1];
	PermutatedText[21 - 1] = TextToPermutate[54 - 1];
	PermutatedText[22 - 1] = TextToPermutate[22 - 1];
	PermutatedText[23 - 1] = TextToPermutate[62 - 1];
	PermutatedText[24 - 1] = TextToPermutate[30 - 1];

	//4
	PermutatedText[25 - 1] = TextToPermutate[37 - 1];
	PermutatedText[26 - 1] = TextToPermutate[5 - 1];
	PermutatedText[27 - 1] = TextToPermutate[45 - 1];
	PermutatedText[28 - 1] = TextToPermutate[13 - 1];
	PermutatedText[29 - 1] = TextToPermutate[53 - 1];
	PermutatedText[30 - 1] = TextToPermutate[21 - 1];
	PermutatedText[31 - 1] = TextToPermutate[61 - 1];
	PermutatedText[32 - 1] = TextToPermutate[29 - 1];

	//5
	PermutatedText[33 - 1] = TextToPermutate[36 - 1];
	PermutatedText[34 - 1] = TextToPermutate[4 - 1];
	PermutatedText[35 - 1] = TextToPermutate[44 - 1];
	PermutatedText[36 - 1] = TextToPermutate[12 - 1];
	PermutatedText[37 - 1] = TextToPermutate[52 - 1];
	PermutatedText[38 - 1] = TextToPermutate[20 - 1];
	PermutatedText[39 - 1] = TextToPermutate[60 - 1];
	PermutatedText[40 - 1] = TextToPermutate[28 - 1];

	//6
	PermutatedText[41 - 1] = TextToPermutate[35 - 1];
	PermutatedText[42 - 1] = TextToPermutate[3 - 1];
	PermutatedText[43 - 1] = TextToPermutate[43 - 1];
	PermutatedText[44 - 1] = TextToPermutate[11 - 1];
	PermutatedText[45 - 1] = TextToPermutate[51 - 1];
	PermutatedText[46 - 1] = TextToPermutate[19 - 1];
	PermutatedText[47 - 1] = TextToPermutate[59 - 1];
	PermutatedText[48 - 1] = TextToPermutate[27 - 1];

	//7
	PermutatedText[49 - 1] = TextToPermutate[34 - 1];
	PermutatedText[50 - 1] = TextToPermutate[2 - 1];
	PermutatedText[51 - 1] = TextToPermutate[42 - 1];
	PermutatedText[52 - 1] = TextToPermutate[10 - 1];
	PermutatedText[53 - 1] = TextToPermutate[50 - 1];
	PermutatedText[54 - 1] = TextToPermutate[18 - 1];
	PermutatedText[55 - 1] = TextToPermutate[58 - 1];
	PermutatedText[56 - 1] = TextToPermutate[26 - 1];

	//8
	PermutatedText[57 - 1] = TextToPermutate[33 - 1];
	PermutatedText[58 - 1] = TextToPermutate[1 - 1];
	PermutatedText[59 - 1] = TextToPermutate[41 - 1];
	PermutatedText[60 - 1] = TextToPermutate[9 - 1];
	PermutatedText[61 - 1] = TextToPermutate[49 - 1];
	PermutatedText[62 - 1] = TextToPermutate[17 - 1];
	PermutatedText[63 - 1] = TextToPermutate[57 - 1];
	PermutatedText[64 - 1] = TextToPermutate[25 - 1];

	return PermutatedText;
}


std::string ManglerXOR(string Text_Round_Right, string MangledText)
{

	for (int bitIndex = 0; bitIndex < 32; bitIndex++) // bits 0-31
	{
		if (Text_Round_Right[bitIndex] == MangledText[bitIndex])
		{
			Text_Round_Right[bitIndex] = '0';
		}
		else
		{
			Text_Round_Right[bitIndex] = '1';
		}
	}

	return Text_Round_Right;
}


std::string ManglerFinalPermute(string TextToPermutate)
{
	string PermutatedText = "11112222333344445555666677778888"; //32 bits long
	// Input 32 bits, output 32 bits

	// 1
	PermutatedText[1 - 1] = TextToPermutate[16 - 1];
	PermutatedText[2 - 1] = TextToPermutate[7 - 1];
	PermutatedText[3 - 1] = TextToPermutate[20 - 1];
	PermutatedText[4 - 1] = TextToPermutate[21 - 1];
	PermutatedText[5 - 1] = TextToPermutate[29 - 1];
	PermutatedText[6 - 1] = TextToPermutate[12 - 1];
	PermutatedText[7 - 1] = TextToPermutate[28 - 1];
	PermutatedText[8 - 1] = TextToPermutate[17 - 1];
	PermutatedText[9 - 1] = TextToPermutate[1 - 1];
	PermutatedText[10 - 1] = TextToPermutate[15 - 1];
	PermutatedText[11 - 1] = TextToPermutate[23 - 1];
	PermutatedText[12 - 1] = TextToPermutate[26 - 1];
	PermutatedText[13 - 1] = TextToPermutate[5 - 1];
	PermutatedText[14 - 1] = TextToPermutate[18 - 1];
	PermutatedText[15 - 1] = TextToPermutate[31 - 1];
	PermutatedText[16 - 1] = TextToPermutate[10 - 1];
	PermutatedText[17 - 1] = TextToPermutate[2 - 1];
	PermutatedText[18 - 1] = TextToPermutate[8 - 1];
	PermutatedText[19 - 1] = TextToPermutate[24 - 1];
	PermutatedText[20 - 1] = TextToPermutate[14 - 1];
	PermutatedText[21 - 1] = TextToPermutate[32 - 1];
	PermutatedText[22 - 1] = TextToPermutate[27 - 1];
	PermutatedText[23 - 1] = TextToPermutate[3 - 1];
	PermutatedText[24 - 1] = TextToPermutate[9 - 1];
	PermutatedText[25 - 1] = TextToPermutate[19 - 1];
	PermutatedText[26 - 1] = TextToPermutate[13 - 1];
	PermutatedText[27 - 1] = TextToPermutate[30 - 1];
	PermutatedText[28 - 1] = TextToPermutate[6 - 1];
	PermutatedText[29 - 1] = TextToPermutate[22 - 1];
	PermutatedText[30 - 1] = TextToPermutate[11 - 1];
	PermutatedText[31 - 1] = TextToPermutate[4 - 1];
	PermutatedText[32 - 1] = TextToPermutate[25 - 1];


	return PermutatedText;
}


std::string SBOX_A(string Input48Text)
{
	// Takes a 48 bit input, and inserts the correct characters into the
	// 4 bit input
	// BITS 1-6 - > BITS 1-4
	string InputBits = "";
	string OutputText = ""; // 4 bits output

	InputBits.assign(Input48Text, (2 - 1), 4); // bits 2-5

	if ((Input48Text[1 - 1] == '0') && (Input48Text[6 - 1] == '0')) // bits 1 and 6
	{
		if (InputBits == "0000") { OutputText = "1110"; }
		if (InputBits == "0001") { OutputText = "0100"; }
		if (InputBits == "0010") { OutputText = "1101"; }
		if (InputBits == "0011") { OutputText = "0001"; }
		if (InputBits == "0100") { OutputText = "0010"; }
		if (InputBits == "0101") { OutputText = "1111"; }
		if (InputBits == "0110") { OutputText = "1011"; }
		if (InputBits == "0111") { OutputText = "1000"; }
		if (InputBits == "1000") { OutputText = "0011"; }
		if (InputBits == "1001") { OutputText = "1010"; }
		if (InputBits == "1010") { OutputText = "0110"; }
		if (InputBits == "1011") { OutputText = "1100"; }
		if (InputBits == "1100") { OutputText = "0101"; }
		if (InputBits == "1101") { OutputText = "1001"; }
		if (InputBits == "1110") { OutputText = "0000"; }
		if (InputBits == "1111") { OutputText = "0111"; }
	}


	if ((Input48Text[1 - 1] == '0') && (Input48Text[6 - 1] == '1')) // bits 1 and 6
	{
		if (InputBits == "0000") { OutputText = "0000"; }
		if (InputBits == "0001") { OutputText = "1111"; }
		if (InputBits == "0010") { OutputText = "0111"; }
		if (InputBits == "0011") { OutputText = "0100"; }
		if (InputBits == "0100") { OutputText = "1110"; }
		if (InputBits == "0101") { OutputText = "0010"; }
		if (InputBits == "0110") { OutputText = "1101"; }
		if (InputBits == "0111") { OutputText = "0001"; }
		if (InputBits == "1000") { OutputText = "1010"; }
		if (InputBits == "1001") { OutputText = "0110"; }
		if (InputBits == "1010") { OutputText = "1100"; }
		if (InputBits == "1011") { OutputText = "1011"; }
		if (InputBits == "1100") { OutputText = "1001"; }
		if (InputBits == "1101") { OutputText = "0101"; }
		if (InputBits == "1110") { OutputText = "0011"; }
		if (InputBits == "1111") { OutputText = "1000"; }
	}


	if ((Input48Text[1 - 1] == '1') && (Input48Text[6 - 1] == '0')) // bits 1 and 6
	{
		if (InputBits == "0000") { OutputText = "0100"; }
		if (InputBits == "0001") { OutputText = "0001"; }
		if (InputBits == "0010") { OutputText = "1110"; }
		if (InputBits == "0011") { OutputText = "1000"; }
		if (InputBits == "0100") { OutputText = "1101"; }
		if (InputBits == "0101") { OutputText = "0110"; }
		if (InputBits == "0110") { OutputText = "0010"; }
		if (InputBits == "0111") { OutputText = "1011"; }
		if (InputBits == "1000") { OutputText = "1111"; }
		if (InputBits == "1001") { OutputText = "1100"; }
		if (InputBits == "1010") { OutputText = "1001"; }
		if (InputBits == "1011") { OutputText = "0111"; }
		if (InputBits == "1100") { OutputText = "0011"; }
		if (InputBits == "1101") { OutputText = "1010"; }
		if (InputBits == "1110") { OutputText = "0101"; }
		if (InputBits == "1111") { OutputText = "0000"; }
	}


	if ((Input48Text[1 - 1] == '1') && (Input48Text[6 - 1] == '1')) // bits 1 and 6
	{
		if (InputBits == "0000") { OutputText = "1111"; }
		if (InputBits == "0001") { OutputText = "1100"; }
		if (InputBits == "0010") { OutputText = "1000"; }
		if (InputBits == "0011") { OutputText = "0010"; }
		if (InputBits == "0100") { OutputText = "0100"; }
		if (InputBits == "0101") { OutputText = "1001"; }
		if (InputBits == "0110") { OutputText = "0001"; }
		if (InputBits == "0111") { OutputText = "0111"; }
		if (InputBits == "1000") { OutputText = "0101"; }
		if (InputBits == "1001") { OutputText = "1011"; }
		if (InputBits == "1010") { OutputText = "0011"; }
		if (InputBits == "1011") { OutputText = "1110"; }
		if (InputBits == "1100") { OutputText = "1010"; }
		if (InputBits == "1101") { OutputText = "0000"; }
		if (InputBits == "1110") { OutputText = "0110"; }
		if (InputBits == "1111") { OutputText = "1101"; }
	}


	return OutputText;
}


std::string SBOX_B(string Input48Text)
{
	// Takes a 48 bit input, and inserts the correct bits into the
	// 4 bit input

	string InputBits = "";
	string OutputText = ""; // 4 bits output
	int FirstBit;
	int LastBit;

	// Bits 7-12
	FirstBit = 7;
	LastBit = 12;
	InputBits.assign(Input48Text, (8 - 1), 4); // bits 8-11

	if ((Input48Text[FirstBit - 1] == '0') && (Input48Text[LastBit - 1] == '0'))
	{
		if (InputBits == "0000") { OutputText = "1111"; }
		if (InputBits == "0001") { OutputText = "0001"; }
		if (InputBits == "0010") { OutputText = "1000"; }
		if (InputBits == "0011") { OutputText = "1110"; }
		if (InputBits == "0100") { OutputText = "0110"; }
		if (InputBits == "0101") { OutputText = "1011"; }
		if (InputBits == "0110") { OutputText = "0011"; }
		if (InputBits == "0111") { OutputText = "0100"; }
		if (InputBits == "1000") { OutputText = "1001"; }
		if (InputBits == "1001") { OutputText = "0111"; }
		if (InputBits == "1010") { OutputText = "0010"; }
		if (InputBits == "1011") { OutputText = "1101"; }
		if (InputBits == "1100") { OutputText = "1100"; }
		if (InputBits == "1101") { OutputText = "0000"; }
		if (InputBits == "1110") { OutputText = "0101"; }
		if (InputBits == "1111") { OutputText = "1010"; }
	}


	if ((Input48Text[FirstBit - 1] == '0') && (Input48Text[LastBit - 1] == '1'))
	{
		if (InputBits == "0000") { OutputText = "0011"; }
		if (InputBits == "0001") { OutputText = "1101"; }
		if (InputBits == "0010") { OutputText = "0100"; }
		if (InputBits == "0011") { OutputText = "0111"; }
		if (InputBits == "0100") { OutputText = "1111"; }
		if (InputBits == "0101") { OutputText = "0010"; }
		if (InputBits == "0110") { OutputText = "1000"; }
		if (InputBits == "0111") { OutputText = "1110"; }
		if (InputBits == "1000") { OutputText = "1100"; }
		if (InputBits == "1001") { OutputText = "0000"; }
		if (InputBits == "1010") { OutputText = "0001"; }
		if (InputBits == "1011") { OutputText = "1010"; }
		if (InputBits == "1100") { OutputText = "0110"; }
		if (InputBits == "1101") { OutputText = "1001"; }
		if (InputBits == "1110") { OutputText = "1011"; }
		if (InputBits == "1111") { OutputText = "0101"; }
	}


	if ((Input48Text[FirstBit - 1] == '1') && (Input48Text[LastBit - 1] == '0'))
	{
		if (InputBits == "0000") { OutputText = "0000"; }
		if (InputBits == "0001") { OutputText = "1110"; }
		if (InputBits == "0010") { OutputText = "0111"; }
		if (InputBits == "0011") { OutputText = "1011"; }
		if (InputBits == "0100") { OutputText = "1010"; }
		if (InputBits == "0101") { OutputText = "0100"; }
		if (InputBits == "0110") { OutputText = "1101"; }
		if (InputBits == "0111") { OutputText = "0001"; }
		if (InputBits == "1000") { OutputText = "0101"; }
		if (InputBits == "1001") { OutputText = "1000"; }
		if (InputBits == "1010") { OutputText = "1100"; }
		if (InputBits == "1011") { OutputText = "0110"; }
		if (InputBits == "1100") { OutputText = "1001"; }
		if (InputBits == "1101") { OutputText = "0011"; }
		if (InputBits == "1110") { OutputText = "0010"; }
		if (InputBits == "1111") { OutputText = "1111"; }
	}


	if ((Input48Text[FirstBit - 1] == '1') && (Input48Text[LastBit - 1] == '1'))
	{
		if (InputBits == "0000") { OutputText = "1101"; }
		if (InputBits == "0001") { OutputText = "1000"; }
		if (InputBits == "0010") { OutputText = "1010"; }
		if (InputBits == "0011") { OutputText = "0001"; }
		if (InputBits == "0100") { OutputText = "0011"; }
		if (InputBits == "0101") { OutputText = "1111"; }
		if (InputBits == "0110") { OutputText = "0100"; }
		if (InputBits == "0111") { OutputText = "0010"; }
		if (InputBits == "1000") { OutputText = "1011"; }
		if (InputBits == "1001") { OutputText = "0110"; }
		if (InputBits == "1010") { OutputText = "0111"; }
		if (InputBits == "1011") { OutputText = "1100"; }
		if (InputBits == "1100") { OutputText = "0000"; }
		if (InputBits == "1101") { OutputText = "0101"; }
		if (InputBits == "1110") { OutputText = "1110"; }
		if (InputBits == "1111") { OutputText = "1001"; }
	}


	return OutputText;
}


std::string SBOX_C(string Input48Text)
{
	// Takes a 48 bit input, and inserts the correct bits into the
	// 4 bit input

	string InputBits = "";
	string OutputText = ""; // 4 bits output
	int FirstBit;
	int LastBit;

	// Bits 13-18
	FirstBit = 13;
	LastBit = 18;
	InputBits.assign(Input48Text, (14 - 1), 4); // bits 14-17

	if ((Input48Text[FirstBit - 1] == '0') && (Input48Text[LastBit - 1] == '0'))
	{
		if (InputBits == "0000") { OutputText = "1010"; }
		if (InputBits == "0001") { OutputText = "0000"; }
		if (InputBits == "0010") { OutputText = "1001"; }
		if (InputBits == "0011") { OutputText = "1110"; }
		if (InputBits == "0100") { OutputText = "0110"; }
		if (InputBits == "0101") { OutputText = "0011"; }
		if (InputBits == "0110") { OutputText = "1111"; }
		if (InputBits == "0111") { OutputText = "0101"; }
		if (InputBits == "1000") { OutputText = "0001"; }
		if (InputBits == "1001") { OutputText = "1101"; }
		if (InputBits == "1010") { OutputText = "1100"; }
		if (InputBits == "1011") { OutputText = "0111"; }
		if (InputBits == "1100") { OutputText = "1011"; }
		if (InputBits == "1101") { OutputText = "0100"; }
		if (InputBits == "1110") { OutputText = "0010"; }
		if (InputBits == "1111") { OutputText = "1000"; }
	}


	if ((Input48Text[FirstBit - 1] == '0') && (Input48Text[LastBit - 1] == '1'))
	{
		if (InputBits == "0000") { OutputText = "1101"; }
		if (InputBits == "0001") { OutputText = "0111"; }
		if (InputBits == "0010") { OutputText = "0000"; }
		if (InputBits == "0011") { OutputText = "1001"; }
		if (InputBits == "0100") { OutputText = "0011"; }
		if (InputBits == "0101") { OutputText = "0100"; }
		if (InputBits == "0110") { OutputText = "0110"; }
		if (InputBits == "0111") { OutputText = "1010"; }
		if (InputBits == "1000") { OutputText = "0010"; }
		if (InputBits == "1001") { OutputText = "1000"; }
		if (InputBits == "1010") { OutputText = "0101"; }
		if (InputBits == "1011") { OutputText = "1110"; }
		if (InputBits == "1100") { OutputText = "1100"; }
		if (InputBits == "1101") { OutputText = "1011"; }
		if (InputBits == "1110") { OutputText = "1111"; }
		if (InputBits == "1111") { OutputText = "0001"; }
	}


	if ((Input48Text[FirstBit - 1] == '1') && (Input48Text[LastBit - 1] == '0'))
	{
		if (InputBits == "0000") { OutputText = "1101"; }
		if (InputBits == "0001") { OutputText = "0110"; }
		if (InputBits == "0010") { OutputText = "0100"; }
		if (InputBits == "0011") { OutputText = "1001"; }
		if (InputBits == "0100") { OutputText = "1000"; }
		if (InputBits == "0101") { OutputText = "1111"; }
		if (InputBits == "0110") { OutputText = "0011"; }
		if (InputBits == "0111") { OutputText = "0000"; }
		if (InputBits == "1000") { OutputText = "1011"; }
		if (InputBits == "1001") { OutputText = "0001"; }
		if (InputBits == "1010") { OutputText = "0010"; }
		if (InputBits == "1011") { OutputText = "1100"; }
		if (InputBits == "1100") { OutputText = "0101"; }
		if (InputBits == "1101") { OutputText = "1010"; }
		if (InputBits == "1110") { OutputText = "1110"; }
		if (InputBits == "1111") { OutputText = "0111"; }
	}


	if ((Input48Text[FirstBit - 1] == '1') && (Input48Text[LastBit - 1] == '1'))
	{
		if (InputBits == "0000") { OutputText = "0001"; }
		if (InputBits == "0001") { OutputText = "1010"; }
		if (InputBits == "0010") { OutputText = "1101"; }
		if (InputBits == "0011") { OutputText = "0000"; }
		if (InputBits == "0100") { OutputText = "0110"; }
		if (InputBits == "0101") { OutputText = "1001"; }
		if (InputBits == "0110") { OutputText = "1000"; }
		if (InputBits == "0111") { OutputText = "0111"; }
		if (InputBits == "1000") { OutputText = "0100"; }
		if (InputBits == "1001") { OutputText = "1111"; }
		if (InputBits == "1010") { OutputText = "1110"; }
		if (InputBits == "1011") { OutputText = "0011"; }
		if (InputBits == "1100") { OutputText = "1011"; }
		if (InputBits == "1101") { OutputText = "0101"; }
		if (InputBits == "1110") { OutputText = "0010"; }
		if (InputBits == "1111") { OutputText = "1100"; }
	}


	return OutputText;
}


std::string SBOX_D(string Input48Text)
{
	// Takes a 48 bit input, and inserts the correct bits into the
	// 4 bit input

	string InputBits = "";
	string OutputText = ""; // 4 bits output
	int FirstBit;
	int LastBit;

	// Bits 19-24
	FirstBit = 19;
	LastBit = 24;
	InputBits.assign(Input48Text, (20 - 1), 4); // bits 21-23

	if ((Input48Text[FirstBit - 1] == '0') && (Input48Text[LastBit - 1] == '0'))
	{
		if (InputBits == "0000") { OutputText = "0111"; }
		if (InputBits == "0001") { OutputText = "1101"; }
		if (InputBits == "0010") { OutputText = "1110"; }
		if (InputBits == "0011") { OutputText = "0011"; }
		if (InputBits == "0100") { OutputText = "0000"; }
		if (InputBits == "0101") { OutputText = "0110"; }
		if (InputBits == "0110") { OutputText = "1001"; }
		if (InputBits == "0111") { OutputText = "1010"; }
		if (InputBits == "1000") { OutputText = "0001"; }
		if (InputBits == "1001") { OutputText = "0010"; }
		if (InputBits == "1010") { OutputText = "1000"; }
		if (InputBits == "1011") { OutputText = "0101"; }
		if (InputBits == "1100") { OutputText = "1011"; }
		if (InputBits == "1101") { OutputText = "1100"; }
		if (InputBits == "1110") { OutputText = "0100"; }
		if (InputBits == "1111") { OutputText = "1111"; }
	}


	if ((Input48Text[FirstBit - 1] == '0') && (Input48Text[LastBit - 1] == '1'))
	{
		if (InputBits == "0000") { OutputText = "1101"; }
		if (InputBits == "0001") { OutputText = "1000"; }
		if (InputBits == "0010") { OutputText = "1011"; }
		if (InputBits == "0011") { OutputText = "0101"; }
		if (InputBits == "0100") { OutputText = "0110"; }
		if (InputBits == "0101") { OutputText = "1111"; }
		if (InputBits == "0110") { OutputText = "0000"; }
		if (InputBits == "0111") { OutputText = "0011"; }
		if (InputBits == "1000") { OutputText = "0100"; }
		if (InputBits == "1001") { OutputText = "0111"; }
		if (InputBits == "1010") { OutputText = "0010"; }
		if (InputBits == "1011") { OutputText = "1100"; }
		if (InputBits == "1100") { OutputText = "0001"; }
		if (InputBits == "1101") { OutputText = "1010"; }
		if (InputBits == "1110") { OutputText = "1110"; }
		if (InputBits == "1111") { OutputText = "1001"; }
	}


	if ((Input48Text[FirstBit - 1] == '1') && (Input48Text[LastBit - 1] == '0'))
	{
		if (InputBits == "0000") { OutputText = "1010"; }
		if (InputBits == "0001") { OutputText = "0110"; }
		if (InputBits == "0010") { OutputText = "1001"; }
		if (InputBits == "0011") { OutputText = "0000"; }
		if (InputBits == "0100") { OutputText = "1100"; }
		if (InputBits == "0101") { OutputText = "1011"; }
		if (InputBits == "0110") { OutputText = "0111"; }
		if (InputBits == "0111") { OutputText = "1101"; }
		if (InputBits == "1000") { OutputText = "1111"; }
		if (InputBits == "1001") { OutputText = "0001"; }
		if (InputBits == "1010") { OutputText = "0011"; }
		if (InputBits == "1011") { OutputText = "1110"; }
		if (InputBits == "1100") { OutputText = "0101"; }
		if (InputBits == "1101") { OutputText = "0010"; }
		if (InputBits == "1110") { OutputText = "1000"; }
		if (InputBits == "1111") { OutputText = "0100"; }
	}


	if ((Input48Text[FirstBit - 1] == '1') && (Input48Text[LastBit - 1] == '1'))
	{
		if (InputBits == "0000") { OutputText = "0011"; }
		if (InputBits == "0001") { OutputText = "1111"; }
		if (InputBits == "0010") { OutputText = "0000"; }
		if (InputBits == "0011") { OutputText = "0110"; }
		if (InputBits == "0100") { OutputText = "1010"; }
		if (InputBits == "0101") { OutputText = "0001"; }
		if (InputBits == "0110") { OutputText = "1101"; }
		if (InputBits == "0111") { OutputText = "1000"; }
		if (InputBits == "1000") { OutputText = "1001"; }
		if (InputBits == "1001") { OutputText = "0100"; }
		if (InputBits == "1010") { OutputText = "0101"; }
		if (InputBits == "1011") { OutputText = "1011"; }
		if (InputBits == "1100") { OutputText = "1100"; }
		if (InputBits == "1101") { OutputText = "0111"; }
		if (InputBits == "1110") { OutputText = "0010"; }
		if (InputBits == "1111") { OutputText = "1110"; }
	}


	return OutputText;
}


std::string SBOX_E(string Input48Text)
{
	// Takes a 48 bit input, and inserts the correct bits into the
	// 4 bit input

	string InputBits = "";
	string OutputText = ""; // 4 bits output
	int FirstBit;
	int LastBit;

	// Bits 25-30
	FirstBit = 25;
	LastBit = 30;
	InputBits.assign(Input48Text, (26 - 1), 4); // bits 14-17

	if ((Input48Text[FirstBit - 1] == '0') && (Input48Text[LastBit - 1] == '0'))
	{
		if (InputBits == "0000") { OutputText = "0010"; }
		if (InputBits == "0001") { OutputText = "1100"; }
		if (InputBits == "0010") { OutputText = "0100"; }
		if (InputBits == "0011") { OutputText = "0001"; }
		if (InputBits == "0100") { OutputText = "0111"; }
		if (InputBits == "0101") { OutputText = "1010"; }
		if (InputBits == "0110") { OutputText = "1011"; }
		if (InputBits == "0111") { OutputText = "0110"; }
		if (InputBits == "1000") { OutputText = "1000"; }
		if (InputBits == "1001") { OutputText = "0101"; }
		if (InputBits == "1010") { OutputText = "0011"; }
		if (InputBits == "1011") { OutputText = "1111"; }
		if (InputBits == "1100") { OutputText = "1101"; }
		if (InputBits == "1101") { OutputText = "0000"; }
		if (InputBits == "1110") { OutputText = "1110"; }
		if (InputBits == "1111") { OutputText = "1001"; }
	}


	if ((Input48Text[FirstBit - 1] == '0') && (Input48Text[LastBit - 1] == '1'))
	{
		if (InputBits == "0000") { OutputText = "1110"; }
		if (InputBits == "0001") { OutputText = "1011"; }
		if (InputBits == "0010") { OutputText = "0010"; }
		if (InputBits == "0011") { OutputText = "1100"; }
		if (InputBits == "0100") { OutputText = "0100"; }
		if (InputBits == "0101") { OutputText = "0111"; }
		if (InputBits == "0110") { OutputText = "1101"; }
		if (InputBits == "0111") { OutputText = "0001"; }
		if (InputBits == "1000") { OutputText = "0101"; }
		if (InputBits == "1001") { OutputText = "0000"; }
		if (InputBits == "1010") { OutputText = "1111"; }
		if (InputBits == "1011") { OutputText = "1010"; }
		if (InputBits == "1100") { OutputText = "0011"; }
		if (InputBits == "1101") { OutputText = "1001"; }
		if (InputBits == "1110") { OutputText = "1000"; }
		if (InputBits == "1111") { OutputText = "0110"; }
	}


	if ((Input48Text[FirstBit - 1] == '1') && (Input48Text[LastBit - 1] == '0'))
	{
		if (InputBits == "0000") { OutputText = "0100"; }
		if (InputBits == "0001") { OutputText = "0010"; }
		if (InputBits == "0010") { OutputText = "0001"; }
		if (InputBits == "0011") { OutputText = "1011"; }
		if (InputBits == "0100") { OutputText = "1010"; }
		if (InputBits == "0101") { OutputText = "1101"; }
		if (InputBits == "0110") { OutputText = "0111"; }
		if (InputBits == "0111") { OutputText = "1000"; }
		if (InputBits == "1000") { OutputText = "1111"; }
		if (InputBits == "1001") { OutputText = "1001"; }
		if (InputBits == "1010") { OutputText = "1100"; }
		if (InputBits == "1011") { OutputText = "0101"; }
		if (InputBits == "1100") { OutputText = "0110"; }
		if (InputBits == "1101") { OutputText = "0011"; }
		if (InputBits == "1110") { OutputText = "0000"; }
		if (InputBits == "1111") { OutputText = "1110"; }
	}


	if ((Input48Text[FirstBit - 1] == '1') && (Input48Text[LastBit - 1] == '1'))
	{
		if (InputBits == "0000") { OutputText = "1011"; }
		if (InputBits == "0001") { OutputText = "1000"; }
		if (InputBits == "0010") { OutputText = "1100"; }
		if (InputBits == "0011") { OutputText = "0111"; }
		if (InputBits == "0100") { OutputText = "0001"; }
		if (InputBits == "0101") { OutputText = "1110"; }
		if (InputBits == "0110") { OutputText = "0010"; }
		if (InputBits == "0111") { OutputText = "1101"; }
		if (InputBits == "1000") { OutputText = "0110"; }
		if (InputBits == "1001") { OutputText = "1111"; }
		if (InputBits == "1010") { OutputText = "0000"; }
		if (InputBits == "1011") { OutputText = "1001"; }
		if (InputBits == "1100") { OutputText = "1010"; }
		if (InputBits == "1101") { OutputText = "0100"; }
		if (InputBits == "1110") { OutputText = "0101"; }
		if (InputBits == "1111") { OutputText = "0011"; }
	}


	return OutputText;
}


std::string SBOX_F(string Input48Text)
{
	// Takes a 48 bit input, and inserts the correct bits into the
	// 4 bit input

	string InputBits = "";
	string OutputText = ""; // 4 bits output
	int FirstBit;
	int LastBit;

	// Bits 31-36
	FirstBit = 31;
	LastBit = 36;
	InputBits.assign(Input48Text, (32 - 1), 4); // bits 14-17

	if ((Input48Text[FirstBit - 1] == '0') && (Input48Text[LastBit - 1] == '0'))
	{
		if (InputBits == "0000") { OutputText = "1100"; }
		if (InputBits == "0001") { OutputText = "0001"; }
		if (InputBits == "0010") { OutputText = "1010"; }
		if (InputBits == "0011") { OutputText = "1111"; }
		if (InputBits == "0100") { OutputText = "1001"; }
		if (InputBits == "0101") { OutputText = "0010"; }
		if (InputBits == "0110") { OutputText = "0110"; }
		if (InputBits == "0111") { OutputText = "1000"; }
		if (InputBits == "1000") { OutputText = "0000"; }
		if (InputBits == "1001") { OutputText = "1101"; }
		if (InputBits == "1010") { OutputText = "0011"; }
		if (InputBits == "1011") { OutputText = "0100"; }
		if (InputBits == "1100") { OutputText = "1110"; }
		if (InputBits == "1101") { OutputText = "0111"; }
		if (InputBits == "1110") { OutputText = "0101"; }
		if (InputBits == "1111") { OutputText = "1011"; }
	}


	if ((Input48Text[FirstBit - 1] == '0') && (Input48Text[LastBit - 1] == '1'))
	{
		if (InputBits == "0000") { OutputText = "1010"; }
		if (InputBits == "0001") { OutputText = "1111"; }
		if (InputBits == "0010") { OutputText = "0100"; }
		if (InputBits == "0011") { OutputText = "0010"; }
		if (InputBits == "0100") { OutputText = "0111"; }
		if (InputBits == "0101") { OutputText = "1100"; }
		if (InputBits == "0110") { OutputText = "1001"; }
		if (InputBits == "0111") { OutputText = "0101"; }
		if (InputBits == "1000") { OutputText = "0110"; }
		if (InputBits == "1001") { OutputText = "0001"; }
		if (InputBits == "1010") { OutputText = "1101"; }
		if (InputBits == "1011") { OutputText = "1110"; }
		if (InputBits == "1100") { OutputText = "0000"; }
		if (InputBits == "1101") { OutputText = "1011"; }
		if (InputBits == "1110") { OutputText = "0011"; }
		if (InputBits == "1111") { OutputText = "1000"; }
	}


	if ((Input48Text[FirstBit - 1] == '1') && (Input48Text[LastBit - 1] == '0'))
	{
		if (InputBits == "0000") { OutputText = "1001"; }
		if (InputBits == "0001") { OutputText = "1110"; }
		if (InputBits == "0010") { OutputText = "1111"; }
		if (InputBits == "0011") { OutputText = "0101"; }
		if (InputBits == "0100") { OutputText = "0010"; }
		if (InputBits == "0101") { OutputText = "1000"; }
		if (InputBits == "0110") { OutputText = "1100"; }
		if (InputBits == "0111") { OutputText = "0011"; }
		if (InputBits == "1000") { OutputText = "0111"; }
		if (InputBits == "1001") { OutputText = "0000"; }
		if (InputBits == "1010") { OutputText = "0100"; }
		if (InputBits == "1011") { OutputText = "1010"; }
		if (InputBits == "1100") { OutputText = "0001"; }
		if (InputBits == "1101") { OutputText = "1101"; }
		if (InputBits == "1110") { OutputText = "1011"; }
		if (InputBits == "1111") { OutputText = "0110"; }
	}


	if ((Input48Text[FirstBit - 1] == '1') && (Input48Text[LastBit - 1] == '1'))
	{
		if (InputBits == "0000") { OutputText = "0100"; }
		if (InputBits == "0001") { OutputText = "0011"; }
		if (InputBits == "0010") { OutputText = "0010"; }
		if (InputBits == "0011") { OutputText = "1100"; }
		if (InputBits == "0100") { OutputText = "1001"; }
		if (InputBits == "0101") { OutputText = "0101"; }
		if (InputBits == "0110") { OutputText = "1111"; }
		if (InputBits == "0111") { OutputText = "1010"; }
		if (InputBits == "1000") { OutputText = "1011"; }
		if (InputBits == "1001") { OutputText = "1110"; }
		if (InputBits == "1010") { OutputText = "0001"; }
		if (InputBits == "1011") { OutputText = "0111"; }
		if (InputBits == "1100") { OutputText = "0110"; }
		if (InputBits == "1101") { OutputText = "0000"; }
		if (InputBits == "1110") { OutputText = "1000"; }
		if (InputBits == "1111") { OutputText = "1101"; }
	}


	return OutputText;
}


std::string SBOX_G(string Input48Text)
{
	// Takes a 48 bit input, and inserts the correct bits into the
	// 4 bit input

	string InputBits = "";
	string OutputText = ""; // 4 bits output
	int FirstBit;
	int LastBit;

	// Bits 37-42
	FirstBit = 37;
	LastBit = 42;
	InputBits.assign(Input48Text, (38 - 1), 4); // bits 14-17

	if ((Input48Text[FirstBit - 1] == '0') && (Input48Text[LastBit - 1] == '0'))
	{
		if (InputBits == "0000") { OutputText = "0100"; }
		if (InputBits == "0001") { OutputText = "1011"; }
		if (InputBits == "0010") { OutputText = "0010"; }
		if (InputBits == "0011") { OutputText = "1110"; }
		if (InputBits == "0100") { OutputText = "1111"; }
		if (InputBits == "0101") { OutputText = "0000"; }
		if (InputBits == "0110") { OutputText = "1000"; }
		if (InputBits == "0111") { OutputText = "1101"; }
		if (InputBits == "1000") { OutputText = "0011"; }
		if (InputBits == "1001") { OutputText = "1100"; }
		if (InputBits == "1010") { OutputText = "1001"; }
		if (InputBits == "1011") { OutputText = "0111"; }
		if (InputBits == "1100") { OutputText = "0101"; }
		if (InputBits == "1101") { OutputText = "1010"; }
		if (InputBits == "1110") { OutputText = "0110"; }
		if (InputBits == "1111") { OutputText = "0001"; }
	}


	if ((Input48Text[FirstBit - 1] == '0') && (Input48Text[LastBit - 1] == '1'))
	{
		if (InputBits == "0000") { OutputText = "1101"; }
		if (InputBits == "0001") { OutputText = "0000"; }
		if (InputBits == "0010") { OutputText = "1011"; }
		if (InputBits == "0011") { OutputText = "0111"; }
		if (InputBits == "0100") { OutputText = "0100"; }
		if (InputBits == "0101") { OutputText = "1001"; }
		if (InputBits == "0110") { OutputText = "0001"; }
		if (InputBits == "0111") { OutputText = "1010"; }
		if (InputBits == "1000") { OutputText = "1110"; }
		if (InputBits == "1001") { OutputText = "0011"; }
		if (InputBits == "1010") { OutputText = "0101"; }
		if (InputBits == "1011") { OutputText = "1100"; }
		if (InputBits == "1100") { OutputText = "0010"; }
		if (InputBits == "1101") { OutputText = "1111"; }
		if (InputBits == "1110") { OutputText = "1000"; }
		if (InputBits == "1111") { OutputText = "0110"; }
	}


	if ((Input48Text[FirstBit - 1] == '1') && (Input48Text[LastBit - 1] == '0'))
	{
		if (InputBits == "0000") { OutputText = "0001"; }
		if (InputBits == "0001") { OutputText = "0100"; }
		if (InputBits == "0010") { OutputText = "1011"; }
		if (InputBits == "0011") { OutputText = "1101"; }
		if (InputBits == "0100") { OutputText = "1100"; }
		if (InputBits == "0101") { OutputText = "0011"; }
		if (InputBits == "0110") { OutputText = "0111"; }
		if (InputBits == "0111") { OutputText = "1110"; }
		if (InputBits == "1000") { OutputText = "1010"; }
		if (InputBits == "1001") { OutputText = "1111"; }
		if (InputBits == "1010") { OutputText = "0110"; }
		if (InputBits == "1011") { OutputText = "1000"; }
		if (InputBits == "1100") { OutputText = "0000"; }
		if (InputBits == "1101") { OutputText = "0101"; }
		if (InputBits == "1110") { OutputText = "1001"; }
		if (InputBits == "1111") { OutputText = "0010"; }
	}


	if ((Input48Text[FirstBit - 1] == '1') && (Input48Text[LastBit - 1] == '1'))
	{
		if (InputBits == "0000") { OutputText = "0110"; }
		if (InputBits == "0001") { OutputText = "1011"; }
		if (InputBits == "0010") { OutputText = "1101"; }
		if (InputBits == "0011") { OutputText = "1000"; }
		if (InputBits == "0100") { OutputText = "0001"; }
		if (InputBits == "0101") { OutputText = "0100"; }
		if (InputBits == "0110") { OutputText = "1010"; }
		if (InputBits == "0111") { OutputText = "0111"; }
		if (InputBits == "1000") { OutputText = "1001"; }
		if (InputBits == "1001") { OutputText = "0101"; }
		if (InputBits == "1010") { OutputText = "0000"; }
		if (InputBits == "1011") { OutputText = "1111"; }
		if (InputBits == "1100") { OutputText = "1110"; }
		if (InputBits == "1101") { OutputText = "0010"; }
		if (InputBits == "1110") { OutputText = "0011"; }
		if (InputBits == "1111") { OutputText = "1100"; }
	}


	return OutputText;
}


std::string SBOX_H(string Input48Text)
{
	// Takes a 48 bit input, and inserts the correct bits into the
	// 4 bit input

	string InputBits = "";
	string OutputText = ""; // 4 bits output
	int FirstBit;
	int LastBit;

	// Bits 43-48
	FirstBit = 43;
	LastBit = 48;
	InputBits.assign(Input48Text, (44 - 1), 4); // bits 14-17

	if ((Input48Text[FirstBit - 1] == '0') && (Input48Text[LastBit - 1] == '0'))
	{
		if (InputBits == "0000") { OutputText = "1101"; }
		if (InputBits == "0001") { OutputText = "0010"; }
		if (InputBits == "0010") { OutputText = "1000"; }
		if (InputBits == "0011") { OutputText = "0100"; }
		if (InputBits == "0100") { OutputText = "0110"; }
		if (InputBits == "0101") { OutputText = "1111"; }
		if (InputBits == "0110") { OutputText = "1011"; }
		if (InputBits == "0111") { OutputText = "0001"; }
		if (InputBits == "1000") { OutputText = "1010"; }
		if (InputBits == "1001") { OutputText = "1001"; }
		if (InputBits == "1010") { OutputText = "0011"; }
		if (InputBits == "1011") { OutputText = "1110"; }
		if (InputBits == "1100") { OutputText = "0101"; }
		if (InputBits == "1101") { OutputText = "0000"; }
		if (InputBits == "1110") { OutputText = "1100"; }
		if (InputBits == "1111") { OutputText = "0111"; }
	}


	if ((Input48Text[FirstBit - 1] == '0') && (Input48Text[LastBit - 1] == '1'))
	{
		if (InputBits == "0000") { OutputText = "0001"; }
		if (InputBits == "0001") { OutputText = "1111"; }
		if (InputBits == "0010") { OutputText = "1101"; }
		if (InputBits == "0011") { OutputText = "1000"; }
		if (InputBits == "0100") { OutputText = "1010"; }
		if (InputBits == "0101") { OutputText = "0011"; }
		if (InputBits == "0110") { OutputText = "0111"; }
		if (InputBits == "0111") { OutputText = "0100"; }
		if (InputBits == "1000") { OutputText = "1100"; }
		if (InputBits == "1001") { OutputText = "0101"; }
		if (InputBits == "1010") { OutputText = "0110"; }
		if (InputBits == "1011") { OutputText = "1011"; }
		if (InputBits == "1100") { OutputText = "0000"; }
		if (InputBits == "1101") { OutputText = "1110"; }
		if (InputBits == "1110") { OutputText = "1001"; }
		if (InputBits == "1111") { OutputText = "0010"; }
	}


	if ((Input48Text[FirstBit - 1] == '1') && (Input48Text[LastBit - 1] == '0'))
	{
		if (InputBits == "0000") { OutputText = "0111"; }
		if (InputBits == "0001") { OutputText = "1011"; }
		if (InputBits == "0010") { OutputText = "0100"; }
		if (InputBits == "0011") { OutputText = "0001"; }
		if (InputBits == "0100") { OutputText = "1001"; }
		if (InputBits == "0101") { OutputText = "1100"; }
		if (InputBits == "0110") { OutputText = "1110"; }
		if (InputBits == "0111") { OutputText = "0010"; }
		if (InputBits == "1000") { OutputText = "0000"; }
		if (InputBits == "1001") { OutputText = "0110"; }
		if (InputBits == "1010") { OutputText = "1010"; }
		if (InputBits == "1011") { OutputText = "1101"; }
		if (InputBits == "1100") { OutputText = "1111"; }
		if (InputBits == "1101") { OutputText = "0011"; }
		if (InputBits == "1110") { OutputText = "0101"; }
		if (InputBits == "1111") { OutputText = "1000"; }
	}


	if ((Input48Text[FirstBit - 1] == '1') && (Input48Text[LastBit - 1] == '1'))
	{
		if (InputBits == "0000") { OutputText = "0010"; }
		if (InputBits == "0001") { OutputText = "0001"; }
		if (InputBits == "0010") { OutputText = "1110"; }
		if (InputBits == "0011") { OutputText = "0111"; }
		if (InputBits == "0100") { OutputText = "0100"; }
		if (InputBits == "0101") { OutputText = "1010"; }
		if (InputBits == "0110") { OutputText = "1000"; }
		if (InputBits == "0111") { OutputText = "1101"; }
		if (InputBits == "1000") { OutputText = "1111"; }
		if (InputBits == "1001") { OutputText = "1100"; }
		if (InputBits == "1010") { OutputText = "1001"; }
		if (InputBits == "1011") { OutputText = "0000"; }
		if (InputBits == "1100") { OutputText = "0011"; }
		if (InputBits == "1101") { OutputText = "0101"; }
		if (InputBits == "1110") { OutputText = "0110"; }
		if (InputBits == "1111") { OutputText = "1011"; }
	}


	return OutputText;
}


std::string BitExpansion(string InputText)
{
	string OutputText = "";

	// Input 32 bits
	// Output 48 bits
	// 1111 > 811112 > 32, 1-5
	// 2222 > 122223 > 4-9
	// 3333 > 233334 > 8-13
	// 4444 > 344445 > 12-17
	// 5555 > 455556 > 16-21
	// 6666 > 566667 > 20-25
	// 7777 > 677778 > 24-29
	// 8888 > 788881 > 28-32, 1

	OutputText.append(InputText, (32 - 1), 1); // 32
	OutputText.append(InputText, (1 - 1), 5); // 1 - 5
	OutputText.append(InputText, (4 - 1), 6); // 4 - 9
	OutputText.append(InputText, (8 - 1), 6); // 8 - 13
	OutputText.append(InputText, (12 - 1), 6); // 12 - 17
	OutputText.append(InputText, (16 - 1), 6); // 16 - 21
	OutputText.append(InputText, (20 - 1), 6); // 20 - 25
	OutputText.append(InputText, (24 - 1), 6); // 24 - 29
	OutputText.append(InputText, (28 - 1), 5); // 28 - 32
	OutputText.append(InputText, (1 - 1), 1); // 1

	return OutputText;
}


std::string Mangler(string InputText, string Final_Key_Left, string Final_Key_Right)
{
	// 32 bit input, two 24 bit keys, 32 bit output

	string OutputText = "111122223333444455556666777788889999000011112222"; // 48 bits
	string FinalOutputText = "";

	InputText = BitExpansion(InputText); // Expand the 32 bit input to 48 bits

	// XOR'ing the left and right keys with the text:
	for (int bitIndex = 0; bitIndex < 24; bitIndex++) // bits 0-23, left
	{
		if (InputText[bitIndex] == Final_Key_Left[bitIndex])
		{
			OutputText[bitIndex] = '0';
		}
		else
		{
			OutputText[bitIndex] = '1';
		}
	}


	for (int bitIndex = 24; bitIndex < 48; bitIndex++) // bits 24-47, right
	{
		if (InputText[bitIndex] == Final_Key_Right[bitIndex - 24])
		{
			OutputText[bitIndex] = '0';
		}
		else
		{
			OutputText[bitIndex] = '1';
		}
	}



	// S-boxes:
	// Bits 1 - 6 SBOX_A
	// Bits 7 - 12 SBOX_B
	// Bits 13 - 18 SBOX_C
	// Bits 19 - 24 SBOX_D
	// Bits 25 - 30 SBOX_E
	// Bits 31 - 36 SBOX_F
	// Bits 37 - 42 SBOX_G
	// Bits 43 - 48 SBOX_H

	FinalOutputText.append(SBOX_A(OutputText));
	FinalOutputText.append(SBOX_B(OutputText));
	FinalOutputText.append(SBOX_C(OutputText));
	FinalOutputText.append(SBOX_D(OutputText));
	FinalOutputText.append(SBOX_E(OutputText));
	FinalOutputText.append(SBOX_F(OutputText));
	FinalOutputText.append(SBOX_G(OutputText));
	FinalOutputText.append(SBOX_H(OutputText));

	FinalOutputText = ManglerFinalPermute(FinalOutputText);

	return FinalOutputText;
}


std::string Final_Key_Left_Permutation(string TextToPermutate)
{
	string PermutatedText = "111122223333444455556666"; //24 bits long
	// Input 28 bits, output 24 bits

	// 1
	PermutatedText[1 - 1] = TextToPermutate[14 - 1];
	PermutatedText[2 - 1] = TextToPermutate[17 - 1];
	PermutatedText[3 - 1] = TextToPermutate[11 - 1];
	PermutatedText[4 - 1] = TextToPermutate[24 - 1];
	PermutatedText[5 - 1] = TextToPermutate[1 - 1];
	PermutatedText[6 - 1] = TextToPermutate[5 - 1];

	PermutatedText[7 - 1] = TextToPermutate[3 - 1];
	PermutatedText[8 - 1] = TextToPermutate[28 - 1];
	PermutatedText[9 - 1] = TextToPermutate[15 - 1];
	PermutatedText[10 - 1] = TextToPermutate[6 - 1];
	PermutatedText[11 - 1] = TextToPermutate[21 - 1];
	PermutatedText[12 - 1] = TextToPermutate[10 - 1];

	PermutatedText[13 - 1] = TextToPermutate[23 - 1];
	PermutatedText[14 - 1] = TextToPermutate[19 - 1];
	PermutatedText[15 - 1] = TextToPermutate[12 - 1];
	PermutatedText[16 - 1] = TextToPermutate[4 - 1];
	PermutatedText[17 - 1] = TextToPermutate[26 - 1];
	PermutatedText[18 - 1] = TextToPermutate[8 - 1];

	PermutatedText[19 - 1] = TextToPermutate[16 - 1];
	PermutatedText[20 - 1] = TextToPermutate[7 - 1];
	PermutatedText[21 - 1] = TextToPermutate[27 - 1];
	PermutatedText[22 - 1] = TextToPermutate[20 - 1];
	PermutatedText[23 - 1] = TextToPermutate[13 - 1];
	PermutatedText[24 - 1] = TextToPermutate[2 - 1];


	return PermutatedText;
}


std::string Final_Key_Right_Permutation(string TextToPermutate)
{
	string PermutatedText = "111122223333444455556666"; //24 bits long
	// Input 28 bits, output 24 bits
	// In the table in the book, the bits are numbered 29-56
	// In our half key, there are only 28 bits
	// Our numbers should be 1 - 28
	// Our numbers are book numbers - 28
	// Subtract 1 more for the array
	// Book number -29

	// 1
	PermutatedText[1 - 1] = TextToPermutate[41 - 29];
	PermutatedText[2 - 1] = TextToPermutate[52 - 29];
	PermutatedText[3 - 1] = TextToPermutate[31 - 29];
	PermutatedText[4 - 1] = TextToPermutate[37 - 29];
	PermutatedText[5 - 1] = TextToPermutate[47 - 29];
	PermutatedText[6 - 1] = TextToPermutate[55 - 29];

	PermutatedText[7 - 1] = TextToPermutate[30 - 29];
	PermutatedText[8 - 1] = TextToPermutate[40 - 29];
	PermutatedText[9 - 1] = TextToPermutate[51 - 29];
	PermutatedText[10 - 1] = TextToPermutate[45 - 29];
	PermutatedText[11 - 1] = TextToPermutate[33 - 29];
	PermutatedText[12 - 1] = TextToPermutate[48 - 29];

	PermutatedText[13 - 1] = TextToPermutate[44 - 29];
	PermutatedText[14 - 1] = TextToPermutate[49 - 29];
	PermutatedText[15 - 1] = TextToPermutate[39 - 29];
	PermutatedText[16 - 1] = TextToPermutate[56 - 29];
	PermutatedText[17 - 1] = TextToPermutate[34 - 29];
	PermutatedText[18 - 1] = TextToPermutate[53 - 29];

	PermutatedText[19 - 1] = TextToPermutate[46 - 29];
	PermutatedText[20 - 1] = TextToPermutate[42 - 29];
	PermutatedText[21 - 1] = TextToPermutate[50 - 29];
	PermutatedText[22 - 1] = TextToPermutate[36 - 29];
	PermutatedText[23 - 1] = TextToPermutate[29 - 29];
	PermutatedText[24 - 1] = TextToPermutate[32 - 29];


	return PermutatedText;
}


std::string RotateTwo(string TextToPermutate)
{
	string PermutatedText = "1111222233334444555566667777"; //28 bits long
	// Input 64 bits, output 28 bits

	// 1
	PermutatedText[1 - 1] = TextToPermutate[3 - 1];
	PermutatedText[2 - 1] = TextToPermutate[4 - 1];
	PermutatedText[3 - 1] = TextToPermutate[5 - 1];
	PermutatedText[4 - 1] = TextToPermutate[6 - 1];
	PermutatedText[5 - 1] = TextToPermutate[7 - 1];
	PermutatedText[6 - 1] = TextToPermutate[8 - 1];
	PermutatedText[7 - 1] = TextToPermutate[9 - 1];
	PermutatedText[8 - 1] = TextToPermutate[10 - 1];
	PermutatedText[9 - 1] = TextToPermutate[11 - 1];
	PermutatedText[10 - 1] = TextToPermutate[12 - 1];
	PermutatedText[11 - 1] = TextToPermutate[13 - 1];
	PermutatedText[12 - 1] = TextToPermutate[14 - 1];
	PermutatedText[13 - 1] = TextToPermutate[15 - 1];
	PermutatedText[14 - 1] = TextToPermutate[16 - 1];
	PermutatedText[15 - 1] = TextToPermutate[17 - 1];
	PermutatedText[16 - 1] = TextToPermutate[18 - 1];
	PermutatedText[17 - 1] = TextToPermutate[19 - 1];
	PermutatedText[18 - 1] = TextToPermutate[20 - 1];
	PermutatedText[19 - 1] = TextToPermutate[21 - 1];
	PermutatedText[20 - 1] = TextToPermutate[22 - 1];
	PermutatedText[21 - 1] = TextToPermutate[23 - 1];
	PermutatedText[22 - 1] = TextToPermutate[24 - 1];
	PermutatedText[23 - 1] = TextToPermutate[25 - 1];
	PermutatedText[24 - 1] = TextToPermutate[26 - 1];
	PermutatedText[25 - 1] = TextToPermutate[27 - 1];
	PermutatedText[26 - 1] = TextToPermutate[28 - 1];
	PermutatedText[27 - 1] = TextToPermutate[1 - 1];
	PermutatedText[28 - 1] = TextToPermutate[2 - 1];


	return PermutatedText;
}


std::string RotateOne(string TextToPermutate)
{
	string PermutatedText = "1111222233334444555566667777"; //28 bits long
	// Input 64 bits, output 28 bits

	// 1
	PermutatedText[1 - 1] = TextToPermutate[2 - 1];
	PermutatedText[2 - 1] = TextToPermutate[3 - 1];
	PermutatedText[3 - 1] = TextToPermutate[4 - 1];
	PermutatedText[4 - 1] = TextToPermutate[5 - 1];
	PermutatedText[5 - 1] = TextToPermutate[6 - 1];
	PermutatedText[6 - 1] = TextToPermutate[7 - 1];
	PermutatedText[7 - 1] = TextToPermutate[8 - 1];
	PermutatedText[8 - 1] = TextToPermutate[9 - 1];
	PermutatedText[9 - 1] = TextToPermutate[10 - 1];
	PermutatedText[10 - 1] = TextToPermutate[11 - 1];
	PermutatedText[11 - 1] = TextToPermutate[12 - 1];
	PermutatedText[12 - 1] = TextToPermutate[13 - 1];
	PermutatedText[13 - 1] = TextToPermutate[14 - 1];
	PermutatedText[14 - 1] = TextToPermutate[15 - 1];
	PermutatedText[15 - 1] = TextToPermutate[16 - 1];
	PermutatedText[16 - 1] = TextToPermutate[17 - 1];
	PermutatedText[17 - 1] = TextToPermutate[18 - 1];
	PermutatedText[18 - 1] = TextToPermutate[19 - 1];
	PermutatedText[19 - 1] = TextToPermutate[20 - 1];
	PermutatedText[20 - 1] = TextToPermutate[21 - 1];
	PermutatedText[21 - 1] = TextToPermutate[22 - 1];
	PermutatedText[22 - 1] = TextToPermutate[23 - 1];
	PermutatedText[23 - 1] = TextToPermutate[24 - 1];
	PermutatedText[24 - 1] = TextToPermutate[25 - 1];
	PermutatedText[25 - 1] = TextToPermutate[26 - 1];
	PermutatedText[26 - 1] = TextToPermutate[27 - 1];
	PermutatedText[27 - 1] = TextToPermutate[28 - 1];
	PermutatedText[28 - 1] = TextToPermutate[1 - 1];


	return PermutatedText;
}


std::string DES_Initial_Permutation_Left(string TextToPermutate)
{
	string PermutatedText = "1111222233334444555566667777"; //28 bits long
	// Input 64 bits, output 28 bits

	// 1
	PermutatedText[1 - 1] = TextToPermutate[57 - 1];
	PermutatedText[2 - 1] = TextToPermutate[49 - 1];
	PermutatedText[3 - 1] = TextToPermutate[41 - 1];
	PermutatedText[4 - 1] = TextToPermutate[33 - 1];
	PermutatedText[5 - 1] = TextToPermutate[25 - 1];
	PermutatedText[6 - 1] = TextToPermutate[17 - 1];
	PermutatedText[7 - 1] = TextToPermutate[9 - 1];

	PermutatedText[8 - 1] = TextToPermutate[1 - 1];
	PermutatedText[9 - 1] = TextToPermutate[58 - 1];
	PermutatedText[10 - 1] = TextToPermutate[50 - 1];
	PermutatedText[11 - 1] = TextToPermutate[42 - 1];
	PermutatedText[12 - 1] = TextToPermutate[34 - 1];
	PermutatedText[13 - 1] = TextToPermutate[26 - 1];
	PermutatedText[14 - 1] = TextToPermutate[18 - 1];

	PermutatedText[15 - 1] = TextToPermutate[10 - 1];
	PermutatedText[16 - 1] = TextToPermutate[2 - 1];
	PermutatedText[17 - 1] = TextToPermutate[59 - 1];
	PermutatedText[18 - 1] = TextToPermutate[51 - 1];
	PermutatedText[19 - 1] = TextToPermutate[43 - 1];
	PermutatedText[20 - 1] = TextToPermutate[35 - 1];
	PermutatedText[21 - 1] = TextToPermutate[27 - 1];

	PermutatedText[22 - 1] = TextToPermutate[19 - 1];
	PermutatedText[23 - 1] = TextToPermutate[11 - 1];
	PermutatedText[24 - 1] = TextToPermutate[3 - 1];
	PermutatedText[25 - 1] = TextToPermutate[60 - 1];
	PermutatedText[26 - 1] = TextToPermutate[52 - 1];
	PermutatedText[27 - 1] = TextToPermutate[44 - 1];
	PermutatedText[28 - 1] = TextToPermutate[36 - 1];


	return PermutatedText;
}


std::string DES_Initial_Permutation_Right(string TextToPermutate)
{
	string PermutatedText = "1111222233334444555566667777"; //28 bits long
	// Input 64 bits, output 28 bits

	// 1
	PermutatedText[1 - 1] = TextToPermutate[63 - 1];
	PermutatedText[2 - 1] = TextToPermutate[55 - 1];
	PermutatedText[3 - 1] = TextToPermutate[47 - 1];
	PermutatedText[4 - 1] = TextToPermutate[39 - 1];
	PermutatedText[5 - 1] = TextToPermutate[31 - 1];
	PermutatedText[6 - 1] = TextToPermutate[23 - 1];
	PermutatedText[7 - 1] = TextToPermutate[15 - 1];

	PermutatedText[8 - 1] = TextToPermutate[7 - 1];
	PermutatedText[9 - 1] = TextToPermutate[62 - 1];
	PermutatedText[10 - 1] = TextToPermutate[54 - 1];
	PermutatedText[11 - 1] = TextToPermutate[46 - 1];
	PermutatedText[12 - 1] = TextToPermutate[38 - 1];
	PermutatedText[13 - 1] = TextToPermutate[30 - 1];
	PermutatedText[14 - 1] = TextToPermutate[22 - 1];

	PermutatedText[15 - 1] = TextToPermutate[14 - 1];
	PermutatedText[16 - 1] = TextToPermutate[6 - 1];
	PermutatedText[17 - 1] = TextToPermutate[61 - 1];
	PermutatedText[18 - 1] = TextToPermutate[53 - 1];
	PermutatedText[19 - 1] = TextToPermutate[45 - 1];
	PermutatedText[20 - 1] = TextToPermutate[37 - 1];
	PermutatedText[21 - 1] = TextToPermutate[29 - 1];

	PermutatedText[22 - 1] = TextToPermutate[21 - 1];
	PermutatedText[23 - 1] = TextToPermutate[13 - 1];
	PermutatedText[24 - 1] = TextToPermutate[5 - 1];
	PermutatedText[25 - 1] = TextToPermutate[28 - 1];
	PermutatedText[26 - 1] = TextToPermutate[20 - 1];
	PermutatedText[27 - 1] = TextToPermutate[12 - 1];
	PermutatedText[28 - 1] = TextToPermutate[4 - 1];


	return PermutatedText;
}


std::string KeyToBinary(string HexToConvert)
{
	string OutputBinary = "";

	for (int CharIndex = 0; CharIndex < HexToConvert.length(); CharIndex++)
	{
		switch (HexToConvert[CharIndex])
		{
		case '0': OutputBinary.append("0000"); break;
		case '1': OutputBinary.append("0001"); break;
		case '2': OutputBinary.append("0010"); break;
		case '3': OutputBinary.append("0011"); break;
		case '4': OutputBinary.append("0100"); break;
		case '5': OutputBinary.append("0101"); break;
		case '6': OutputBinary.append("0110"); break;
		case '7': OutputBinary.append("0111"); break;
		case '8': OutputBinary.append("1000"); break;
		case '9': OutputBinary.append("1001"); break;
		case 'A': OutputBinary.append("1010"); break;
		case 'B': OutputBinary.append("1011"); break;
		case 'C': OutputBinary.append("1100"); break;
		case 'D': OutputBinary.append("1101"); break;
		case 'E': OutputBinary.append("1110"); break;
		case 'F': OutputBinary.append("1111"); break;
		}


	}

	// Padding 56 bit binary key with 0's as parity bits to make 64 bit binary key
	// bits 8, 16, etc. will be ignored by key initial permutation.
	//
	// 0  1  2  3  4  5  6 << Insert 0, pos 7
	// 7  8  9  10 11 12 13 << Insert 0, pos 14
	// 14 15 16 17 18 19 20 << Insert 0, pos 21
	// 21 22 23 24 25 26 27 << Insert 0, pos 28
	// 28 29 30 31 32 33 34 << Insert 0, pos 35
	// 35 36 37 38 39 40 41 << Insert 0, pos 42
	// 42 43 44 45 46 47 48 << Insert 0, pos 49
	// 49 50 51 52 53 54 55 << Insert 0, pos OutputBinary.end()

	OutputBinary.insert(OutputBinary.end(), 1, '0');
	OutputBinary.insert(49, 1, '0');
	OutputBinary.insert(42, 1, '0');
	OutputBinary.insert(35, 1, '0');
	OutputBinary.insert(28, 1, '0');
	OutputBinary.insert(21, 1, '0');
	OutputBinary.insert(14, 1, '0');
	OutputBinary.insert(7, 1, '0');

	return OutputBinary;
}


std::string HexToBinary(string HexToConvert)
{
	string OutputBinary = "";

	for (int CharIndex = 0; CharIndex < HexToConvert.length(); CharIndex++)
	{
		switch (HexToConvert[CharIndex])
		{
		case '0': OutputBinary.append("0000"); break;
		case '1': OutputBinary.append("0001"); break;
		case '2': OutputBinary.append("0010"); break;
		case '3': OutputBinary.append("0011"); break;
		case '4': OutputBinary.append("0100"); break;
		case '5': OutputBinary.append("0101"); break;
		case '6': OutputBinary.append("0110"); break;
		case '7': OutputBinary.append("0111"); break;
		case '8': OutputBinary.append("1000"); break;
		case '9': OutputBinary.append("1001"); break;
		case 'A': OutputBinary.append("1010"); break;
		case 'B': OutputBinary.append("1011"); break;
		case 'C': OutputBinary.append("1100"); break;
		case 'D': OutputBinary.append("1101"); break;
		case 'E': OutputBinary.append("1110"); break;
		case 'F': OutputBinary.append("1111"); break;
		}


	}


	return OutputBinary;
}


std::string BinaryToHex(string BinaryToConvert)
{
	// Input is 64 bits long
	// 16 chunks of 4 bits each = 16 hex characters

	string OutputHex = "";
	string FourBits = "";
	int FirstBit;

	for (int Round = 0; Round < 16; Round++) // Round 0-15
	{
		// 0-3, 4-7, 8-11, 12-15, ...
		FirstBit = (0 + Round * 4);
		FourBits.assign(BinaryToConvert, FirstBit, 4);
		if (FourBits == "0000") { OutputHex.append("0"); }
		if (FourBits == "0001") { OutputHex.append("1"); }
		if (FourBits == "0010") { OutputHex.append("2"); }
		if (FourBits == "0011") { OutputHex.append("3"); }
		if (FourBits == "0100") { OutputHex.append("4"); }
		if (FourBits == "0101") { OutputHex.append("5"); }
		if (FourBits == "0110") { OutputHex.append("6"); }
		if (FourBits == "0111") { OutputHex.append("7"); }
		if (FourBits == "1000") { OutputHex.append("8"); }
		if (FourBits == "1001") { OutputHex.append("9"); }
		if (FourBits == "1010") { OutputHex.append("A"); }
		if (FourBits == "1011") { OutputHex.append("B"); }
		if (FourBits == "1100") { OutputHex.append("C"); }
		if (FourBits == "1101") { OutputHex.append("D"); }
		if (FourBits == "1110") { OutputHex.append("E"); }
		if (FourBits == "1111") { OutputHex.append("F"); }
	}


	return OutputHex;
}


std::string InitialTextPermutation(string TextToPermutate)
{
	string PermutatedText = TextToPermutate;

	// 1
	PermutatedText[1 - 1] = TextToPermutate[58 - 1];
	PermutatedText[2 - 1] = TextToPermutate[50 - 1];
	PermutatedText[3 - 1] = TextToPermutate[42 - 1];
	PermutatedText[4 - 1] = TextToPermutate[34 - 1];
	PermutatedText[5 - 1] = TextToPermutate[26 - 1];
	PermutatedText[6 - 1] = TextToPermutate[18 - 1];
	PermutatedText[7 - 1] = TextToPermutate[10 - 1];
	PermutatedText[8 - 1] = TextToPermutate[2 - 1];

	//2
	PermutatedText[9 - 1] = TextToPermutate[60 - 1];
	PermutatedText[10 - 1] = TextToPermutate[52 - 1];
	PermutatedText[11 - 1] = TextToPermutate[44 - 1];
	PermutatedText[12 - 1] = TextToPermutate[36 - 1];
	PermutatedText[13 - 1] = TextToPermutate[28 - 1];
	PermutatedText[14 - 1] = TextToPermutate[20 - 1];
	PermutatedText[15 - 1] = TextToPermutate[12 - 1];
	PermutatedText[16 - 1] = TextToPermutate[4 - 1];

	//3
	PermutatedText[17 - 1] = TextToPermutate[62 - 1];
	PermutatedText[18 - 1] = TextToPermutate[54 - 1];
	PermutatedText[19 - 1] = TextToPermutate[46 - 1];
	PermutatedText[20 - 1] = TextToPermutate[38 - 1];
	PermutatedText[21 - 1] = TextToPermutate[30 - 1];
	PermutatedText[22 - 1] = TextToPermutate[22 - 1];
	PermutatedText[23 - 1] = TextToPermutate[14 - 1];
	PermutatedText[24 - 1] = TextToPermutate[6 - 1];

	//4
	PermutatedText[25 - 1] = TextToPermutate[64 - 1];
	PermutatedText[26 - 1] = TextToPermutate[56 - 1];
	PermutatedText[27 - 1] = TextToPermutate[48 - 1];
	PermutatedText[28 - 1] = TextToPermutate[40 - 1];
	PermutatedText[29 - 1] = TextToPermutate[32 - 1];
	PermutatedText[30 - 1] = TextToPermutate[24 - 1];
	PermutatedText[31 - 1] = TextToPermutate[16 - 1];
	PermutatedText[32 - 1] = TextToPermutate[8 - 1];

	//5
	PermutatedText[33 - 1] = TextToPermutate[57 - 1];
	PermutatedText[34 - 1] = TextToPermutate[49 - 1];
	PermutatedText[35 - 1] = TextToPermutate[41 - 1];
	PermutatedText[36 - 1] = TextToPermutate[33 - 1];
	PermutatedText[37 - 1] = TextToPermutate[25 - 1];
	PermutatedText[38 - 1] = TextToPermutate[17 - 1];
	PermutatedText[39 - 1] = TextToPermutate[9 - 1];
	PermutatedText[40 - 1] = TextToPermutate[1 - 1];

	//6
	PermutatedText[41 - 1] = TextToPermutate[59 - 1];
	PermutatedText[42 - 1] = TextToPermutate[51 - 1];
	PermutatedText[43 - 1] = TextToPermutate[43 - 1];
	PermutatedText[44 - 1] = TextToPermutate[35 - 1];
	PermutatedText[45 - 1] = TextToPermutate[27 - 1];
	PermutatedText[46 - 1] = TextToPermutate[19 - 1];
	PermutatedText[47 - 1] = TextToPermutate[11 - 1];
	PermutatedText[48 - 1] = TextToPermutate[3 - 1];

	//7
	PermutatedText[49 - 1] = TextToPermutate[61 - 1];
	PermutatedText[50 - 1] = TextToPermutate[53 - 1];
	PermutatedText[51 - 1] = TextToPermutate[45 - 1];
	PermutatedText[52 - 1] = TextToPermutate[37 - 1];
	PermutatedText[53 - 1] = TextToPermutate[29 - 1];
	PermutatedText[54 - 1] = TextToPermutate[21 - 1];
	PermutatedText[55 - 1] = TextToPermutate[13 - 1];
	PermutatedText[56 - 1] = TextToPermutate[5 - 1];

	//8
	PermutatedText[57 - 1] = TextToPermutate[63 - 1];
	PermutatedText[58 - 1] = TextToPermutate[55 - 1];
	PermutatedText[59 - 1] = TextToPermutate[47 - 1];
	PermutatedText[60 - 1] = TextToPermutate[39 - 1];
	PermutatedText[61 - 1] = TextToPermutate[31 - 1];
	PermutatedText[62 - 1] = TextToPermutate[23 - 1];
	PermutatedText[63 - 1] = TextToPermutate[15 - 1];
	PermutatedText[64 - 1] = TextToPermutate[7 - 1];

	return PermutatedText;
}


std::string DES_Encrypt(string PlainText, string DES_Key)
{
	string BinaryText;
	string DES_Key_Left;
	string DES_Key_Right;
	string Text_Round_Left;
	string Text_Round_Right;
	string Key_Round_Left;
	string Key_Round_Right;
	string Final_Key_Left;
	string Final_Key_Right;
	string MangledText;
	string New_Text_Round_Right;

	BinaryText = HexToBinary(PlainText); // convert plaintext hex to binary
	BinaryText = InitialTextPermutation(BinaryText); // initial plaintext permutation

	DES_Key = KeyToBinary(DES_Key); // convert key to binary and add parity bits
	DES_Key_Left = DES_Initial_Permutation_Left(DES_Key); // initial permutation and left side of key
	DES_Key_Right = DES_Initial_Permutation_Right(DES_Key); // initial permutation and right side of key

	// split the plaintext in half
	Text_Round_Left.append(BinaryText, 0, 32); // first 32 bits of BinaryText
	Text_Round_Right.append(BinaryText, 32, 32); // last 32 bits of BinaryText

	//
	// Round 1
	// *rounds 1, 2, 9, and 16 have left shift of 1*
	DES_Key_Left = RotateOne(DES_Key_Left); // rotate both keys left 1 bit
	DES_Key_Right = RotateOne(DES_Key_Right);
	Final_Key_Left = Final_Key_Left_Permutation(DES_Key_Left); // permute both halves of key (but keep the unpermuted halves for later rotation)
	Final_Key_Right = Final_Key_Right_Permutation(DES_Key_Right);
	MangledText = Mangler(Text_Round_Right, Final_Key_Left, Final_Key_Right); // Mangle the right half
	New_Text_Round_Right = ManglerXOR(Text_Round_Left, MangledText);
	Text_Round_Left = Text_Round_Right;
	Text_Round_Right = New_Text_Round_Right;
	//cout << endl << Text_Round_Left << Text_Round_Right;


	//
	// Round 2
	// *rounds 1, 2, 9, and 16 have left shift of 1*
	DES_Key_Left = RotateOne(DES_Key_Left); // rotate both keys left 1 bit
	DES_Key_Right = RotateOne(DES_Key_Right);
	Final_Key_Left = Final_Key_Left_Permutation(DES_Key_Left); // permute both halves of key (but keep the unpermuted halves for later rotation)
	Final_Key_Right = Final_Key_Right_Permutation(DES_Key_Right);
	MangledText = Mangler(Text_Round_Right, Final_Key_Left, Final_Key_Right); // Mangle the right half
	New_Text_Round_Right = ManglerXOR(Text_Round_Left, MangledText);
	Text_Round_Left = Text_Round_Right;
	Text_Round_Right = New_Text_Round_Right;
	//cout << endl << Text_Round_Left << Text_Round_Right;


	//
	// Round 3
	// *rounds 1, 2, 9, and 16 have left shift of 1*
	DES_Key_Left = RotateTwo(DES_Key_Left); // rotate both keys left 1 bit
	DES_Key_Right = RotateTwo(DES_Key_Right);
	Final_Key_Left = Final_Key_Left_Permutation(DES_Key_Left); // permute both halves of key (but keep the unpermuted halves for later rotation)
	Final_Key_Right = Final_Key_Right_Permutation(DES_Key_Right);
	MangledText = Mangler(Text_Round_Right, Final_Key_Left, Final_Key_Right); // Mangle the right half
	New_Text_Round_Right = ManglerXOR(Text_Round_Left, MangledText);
	Text_Round_Left = Text_Round_Right;
	Text_Round_Right = New_Text_Round_Right;
	//cout << endl << Text_Round_Left << Text_Round_Right;


	//
	// Round 4
	// *rounds 1, 2, 9, and 16 have left shift of 1*
	DES_Key_Left = RotateTwo(DES_Key_Left); // rotate both keys left 1 bit
	DES_Key_Right = RotateTwo(DES_Key_Right);
	Final_Key_Left = Final_Key_Left_Permutation(DES_Key_Left); // permute both halves of key (but keep the unpermuted halves for later rotation)
	Final_Key_Right = Final_Key_Right_Permutation(DES_Key_Right);
	MangledText = Mangler(Text_Round_Right, Final_Key_Left, Final_Key_Right); // Mangle the right half
	New_Text_Round_Right = ManglerXOR(Text_Round_Left, MangledText);
	Text_Round_Left = Text_Round_Right;
	Text_Round_Right = New_Text_Round_Right;
	//cout << endl << Text_Round_Left << Text_Round_Right;


	//
	// Round 5
	// *rounds 1, 2, 9, and 16 have left shift of 1*
	DES_Key_Left = RotateTwo(DES_Key_Left); // rotate both keys left 1 bit
	DES_Key_Right = RotateTwo(DES_Key_Right);
	Final_Key_Left = Final_Key_Left_Permutation(DES_Key_Left); // permute both halves of key (but keep the unpermuted halves for later rotation)
	Final_Key_Right = Final_Key_Right_Permutation(DES_Key_Right);
	MangledText = Mangler(Text_Round_Right, Final_Key_Left, Final_Key_Right); // Mangle the right half
	New_Text_Round_Right = ManglerXOR(Text_Round_Left, MangledText);
	Text_Round_Left = Text_Round_Right;
	Text_Round_Right = New_Text_Round_Right;
	//cout << endl << Text_Round_Left << Text_Round_Right;


	//
	// Round 6
	// *rounds 1, 2, 9, and 16 have left shift of 1*
	DES_Key_Left = RotateTwo(DES_Key_Left); // rotate both keys left 1 bit
	DES_Key_Right = RotateTwo(DES_Key_Right);
	Final_Key_Left = Final_Key_Left_Permutation(DES_Key_Left); // permute both halves of key (but keep the unpermuted halves for later rotation)
	Final_Key_Right = Final_Key_Right_Permutation(DES_Key_Right);
	MangledText = Mangler(Text_Round_Right, Final_Key_Left, Final_Key_Right); // Mangle the right half
	New_Text_Round_Right = ManglerXOR(Text_Round_Left, MangledText);
	Text_Round_Left = Text_Round_Right;
	Text_Round_Right = New_Text_Round_Right;
	//cout << endl << Text_Round_Left << Text_Round_Right;


	//
	// Round 7
	// *rounds 1, 2, 9, and 16 have left shift of 1*
	DES_Key_Left = RotateTwo(DES_Key_Left); // rotate both keys left 1 bit
	DES_Key_Right = RotateTwo(DES_Key_Right);
	Final_Key_Left = Final_Key_Left_Permutation(DES_Key_Left); // permute both halves of key (but keep the unpermuted halves for later rotation)
	Final_Key_Right = Final_Key_Right_Permutation(DES_Key_Right);
	MangledText = Mangler(Text_Round_Right, Final_Key_Left, Final_Key_Right); // Mangle the right half
	New_Text_Round_Right = ManglerXOR(Text_Round_Left, MangledText);
	Text_Round_Left = Text_Round_Right;
	Text_Round_Right = New_Text_Round_Right;
	//cout << endl << Text_Round_Left << Text_Round_Right;


	//
	// Round 8
	// *rounds 1, 2, 9, and 16 have left shift of 1*
	DES_Key_Left = RotateTwo(DES_Key_Left); // rotate both keys left 1 bit
	DES_Key_Right = RotateTwo(DES_Key_Right);
	Final_Key_Left = Final_Key_Left_Permutation(DES_Key_Left); // permute both halves of key (but keep the unpermuted halves for later rotation)
	Final_Key_Right = Final_Key_Right_Permutation(DES_Key_Right);
	MangledText = Mangler(Text_Round_Right, Final_Key_Left, Final_Key_Right); // Mangle the right half
	New_Text_Round_Right = ManglerXOR(Text_Round_Left, MangledText);
	Text_Round_Left = Text_Round_Right;
	Text_Round_Right = New_Text_Round_Right;
	//cout << endl << Text_Round_Left << Text_Round_Right;


	//
	// Round 9
	// *rounds 1, 2, 9, and 16 have left shift of 1*
	DES_Key_Left = RotateOne(DES_Key_Left); // rotate both keys left 1 bit
	DES_Key_Right = RotateOne(DES_Key_Right);
	Final_Key_Left = Final_Key_Left_Permutation(DES_Key_Left); // permute both halves of key (but keep the unpermuted halves for later rotation)
	Final_Key_Right = Final_Key_Right_Permutation(DES_Key_Right);
	MangledText = Mangler(Text_Round_Right, Final_Key_Left, Final_Key_Right); // Mangle the right half
	New_Text_Round_Right = ManglerXOR(Text_Round_Left, MangledText);
	Text_Round_Left = Text_Round_Right;
	Text_Round_Right = New_Text_Round_Right;
	//cout << endl << Text_Round_Left << Text_Round_Right;


	//
	// Round 10
	// *rounds 1, 2, 9, and 16 have left shift of 1*
	DES_Key_Left = RotateTwo(DES_Key_Left); // rotate both keys left 1 bit
	DES_Key_Right = RotateTwo(DES_Key_Right);
	Final_Key_Left = Final_Key_Left_Permutation(DES_Key_Left); // permute both halves of key (but keep the unpermuted halves for later rotation)
	Final_Key_Right = Final_Key_Right_Permutation(DES_Key_Right);
	MangledText = Mangler(Text_Round_Right, Final_Key_Left, Final_Key_Right); // Mangle the right half
	New_Text_Round_Right = ManglerXOR(Text_Round_Left, MangledText);
	Text_Round_Left = Text_Round_Right;
	Text_Round_Right = New_Text_Round_Right;
	//cout << endl << Text_Round_Left << Text_Round_Right;


	//
	// Round 11
	// *rounds 1, 2, 9, and 16 have left shift of 1*
	DES_Key_Left = RotateTwo(DES_Key_Left); // rotate both keys left 1 bit
	DES_Key_Right = RotateTwo(DES_Key_Right);
	Final_Key_Left = Final_Key_Left_Permutation(DES_Key_Left); // permute both halves of key (but keep the unpermuted halves for later rotation)
	Final_Key_Right = Final_Key_Right_Permutation(DES_Key_Right);
	MangledText = Mangler(Text_Round_Right, Final_Key_Left, Final_Key_Right); // Mangle the right half
	New_Text_Round_Right = ManglerXOR(Text_Round_Left, MangledText);
	Text_Round_Left = Text_Round_Right;
	Text_Round_Right = New_Text_Round_Right;
	//cout << endl << Text_Round_Left << Text_Round_Right;


	//
	// Round 12
	// *rounds 1, 2, 9, and 16 have left shift of 1*
	DES_Key_Left = RotateTwo(DES_Key_Left); // rotate both keys left 1 bit
	DES_Key_Right = RotateTwo(DES_Key_Right);
	Final_Key_Left = Final_Key_Left_Permutation(DES_Key_Left); // permute both halves of key (but keep the unpermuted halves for later rotation)
	Final_Key_Right = Final_Key_Right_Permutation(DES_Key_Right);
	MangledText = Mangler(Text_Round_Right, Final_Key_Left, Final_Key_Right); // Mangle the right half
	New_Text_Round_Right = ManglerXOR(Text_Round_Left, MangledText);
	Text_Round_Left = Text_Round_Right;
	Text_Round_Right = New_Text_Round_Right;
	//cout << endl << Text_Round_Left << Text_Round_Right;


	//
	// Round 13
	// *rounds 1, 2, 9, and 16 have left shift of 1*
	DES_Key_Left = RotateTwo(DES_Key_Left); // rotate both keys left 1 bit
	DES_Key_Right = RotateTwo(DES_Key_Right);
	Final_Key_Left = Final_Key_Left_Permutation(DES_Key_Left); // permute both halves of key (but keep the unpermuted halves for later rotation)
	Final_Key_Right = Final_Key_Right_Permutation(DES_Key_Right);
	MangledText = Mangler(Text_Round_Right, Final_Key_Left, Final_Key_Right); // Mangle the right half
	New_Text_Round_Right = ManglerXOR(Text_Round_Left, MangledText);
	Text_Round_Left = Text_Round_Right;
	Text_Round_Right = New_Text_Round_Right;
	//cout << endl << Text_Round_Left << Text_Round_Right;


	//
	// Round 14
	// *rounds 1, 2, 9, and 16 have left shift of 1*
	DES_Key_Left = RotateTwo(DES_Key_Left); // rotate both keys left 1 bit
	DES_Key_Right = RotateTwo(DES_Key_Right);
	Final_Key_Left = Final_Key_Left_Permutation(DES_Key_Left); // permute both halves of key (but keep the unpermuted halves for later rotation)
	Final_Key_Right = Final_Key_Right_Permutation(DES_Key_Right);
	MangledText = Mangler(Text_Round_Right, Final_Key_Left, Final_Key_Right); // Mangle the right half
	New_Text_Round_Right = ManglerXOR(Text_Round_Left, MangledText);
	Text_Round_Left = Text_Round_Right;
	Text_Round_Right = New_Text_Round_Right;
	//cout << endl << Text_Round_Left << Text_Round_Right;


	//
	// Round 15
	// *rounds 1, 2, 9, and 16 have left shift of 1*
	DES_Key_Left = RotateTwo(DES_Key_Left); // rotate both keys left 1 bit
	DES_Key_Right = RotateTwo(DES_Key_Right);
	Final_Key_Left = Final_Key_Left_Permutation(DES_Key_Left); // permute both halves of key (but keep the unpermuted halves for later rotation)
	Final_Key_Right = Final_Key_Right_Permutation(DES_Key_Right);
	MangledText = Mangler(Text_Round_Right, Final_Key_Left, Final_Key_Right); // Mangle the right half
	New_Text_Round_Right = ManglerXOR(Text_Round_Left, MangledText);
	Text_Round_Left = Text_Round_Right;
	Text_Round_Right = New_Text_Round_Right;
	//cout << endl << Text_Round_Left << Text_Round_Right;


	//
	// Round 16
	// *rounds 1, 2, 9, and 16 have left shift of 1*
	DES_Key_Left = RotateOne(DES_Key_Left); // rotate both keys left 1 bit
	DES_Key_Right = RotateOne(DES_Key_Right);
	Final_Key_Left = Final_Key_Left_Permutation(DES_Key_Left); // permute both halves of key (but keep the unpermuted halves for later rotation)
	Final_Key_Right = Final_Key_Right_Permutation(DES_Key_Right);
	MangledText = Mangler(Text_Round_Right, Final_Key_Left, Final_Key_Right); // Mangle the right half
	New_Text_Round_Right = ManglerXOR(Text_Round_Left, MangledText);
	Text_Round_Left = Text_Round_Right;
	Text_Round_Right = New_Text_Round_Right;
	//cout << endl << Text_Round_Left << Text_Round_Right;

	//
	// End of Round 16
	//

	Text_Round_Left.append(Text_Round_Right); // join the two halves back together
	Text_Round_Left = FinalTextPermutation(Text_Round_Left); // final permutation
	Text_Round_Left = BinaryToHex(Text_Round_Left); // return the ciphertext to hex format


	return Text_Round_Left;
}


std::string DES_Decrypt(string CipherText, string DES_Key)
{
	string BinaryText;
	string DES_Key_Left;
	string DES_Key_Right;
	string Text_Round_Left;
	string Text_Round_Right;
	string Key_Round_Left;
	string Key_Round_Right;
	string Final_Key_Left;
	string Final_Key_Right;
	string MangledText;
	string New_Text_Round_Left;
	string DES_Key_Left_1, DES_Key_Right_1;
	string DES_Key_Left_2, DES_Key_Right_2;
	string DES_Key_Left_3, DES_Key_Right_3;
	string DES_Key_Left_4, DES_Key_Right_4;
	string DES_Key_Left_5, DES_Key_Right_5;
	string DES_Key_Left_6, DES_Key_Right_6;
	string DES_Key_Left_7, DES_Key_Right_7;
	string DES_Key_Left_8, DES_Key_Right_8;
	string DES_Key_Left_9, DES_Key_Right_9;
	string DES_Key_Left_10, DES_Key_Right_10;
	string DES_Key_Left_11, DES_Key_Right_11;
	string DES_Key_Left_12, DES_Key_Right_12;
	string DES_Key_Left_13, DES_Key_Right_13;
	string DES_Key_Left_14, DES_Key_Right_14;
	string DES_Key_Left_15, DES_Key_Right_15;
	string DES_Key_Left_16, DES_Key_Right_16;

	BinaryText = HexToBinary(CipherText); // convert plaintext hex to binary
	BinaryText = InitialTextPermutation(BinaryText); // initial plaintext permutation (reverses the final permutation from encryption)

	DES_Key = KeyToBinary(DES_Key); // convert key to binary and add parity bits
	DES_Key_Left = DES_Initial_Permutation_Left(DES_Key); // initial permutation and left side of key
	DES_Key_Right = DES_Initial_Permutation_Right(DES_Key); // initial permutation and right side of key

	// split the plaintext in half
	Text_Round_Left.append(BinaryText, 0, 32); // first 32 bits of BinaryText
	Text_Round_Right.append(BinaryText, 32, 32); // last 32 bits of BinaryText


	// *rounds 1, 2, 9, and 16 have left shift of 1*
	// Key Round 1
	DES_Key_Left_1 = RotateOne(DES_Key_Left); // rotate both keys left 1 bit
	DES_Key_Right_1 = RotateOne(DES_Key_Right);
	// Key Round 2
	DES_Key_Left_2 = RotateOne(DES_Key_Left_1); // rotate both keys left 1 bit
	DES_Key_Right_2 = RotateOne(DES_Key_Right_1);
	// Key Round 3
	DES_Key_Left_3 = RotateTwo(DES_Key_Left_2); // rotate both keys left 2 bit
	DES_Key_Right_3 = RotateTwo(DES_Key_Right_2);
	// Key Round 4
	DES_Key_Left_4 = RotateTwo(DES_Key_Left_3); // rotate both keys left 2 bit
	DES_Key_Right_4 = RotateTwo(DES_Key_Right_3);
	// Key Round 5
	DES_Key_Left_5 = RotateTwo(DES_Key_Left_4); // rotate both keys left 2 bit
	DES_Key_Right_5 = RotateTwo(DES_Key_Right_4);
	// Key Round 6
	DES_Key_Left_6 = RotateTwo(DES_Key_Left_5); // rotate both keys left 2 bit
	DES_Key_Right_6 = RotateTwo(DES_Key_Right_5);
	// Key Round 7
	DES_Key_Left_7 = RotateTwo(DES_Key_Left_6); // rotate both keys left 2 bit
	DES_Key_Right_7 = RotateTwo(DES_Key_Right_6);
	// Key Round 8
	DES_Key_Left_8 = RotateTwo(DES_Key_Left_7); // rotate both keys left 2 bit
	DES_Key_Right_8 = RotateTwo(DES_Key_Right_7);
	// Key Round 9
	DES_Key_Left_9 = RotateOne(DES_Key_Left_8); // rotate both keys left 1 bit
	DES_Key_Right_9 = RotateOne(DES_Key_Right_8);
	// Key Round 10
	DES_Key_Left_10 = RotateTwo(DES_Key_Left_9); // rotate both keys left 2 bit
	DES_Key_Right_10 = RotateTwo(DES_Key_Right_9);
	// Key Round 11
	DES_Key_Left_11 = RotateTwo(DES_Key_Left_10); // rotate both keys left 2 bit
	DES_Key_Right_11 = RotateTwo(DES_Key_Right_10);
	// Key Round 12
	DES_Key_Left_12 = RotateTwo(DES_Key_Left_11); // rotate both keys left 2 bit
	DES_Key_Right_12 = RotateTwo(DES_Key_Right_11);
	// Key Round 13
	DES_Key_Left_13 = RotateTwo(DES_Key_Left_12); // rotate both keys left 2 bit
	DES_Key_Right_13 = RotateTwo(DES_Key_Right_12);
	// Key Round 14
	DES_Key_Left_14 = RotateTwo(DES_Key_Left_13); // rotate both keys left 2 bit
	DES_Key_Right_14 = RotateTwo(DES_Key_Right_13);
	// Key Round 15
	DES_Key_Left_15 = RotateTwo(DES_Key_Left_14); // rotate both keys left 2 bit
	DES_Key_Right_15 = RotateTwo(DES_Key_Right_14);
	// Key Round 16
	DES_Key_Left_16 = RotateOne(DES_Key_Left_15); // rotate both keys left 1 bit
	DES_Key_Right_16 = RotateOne(DES_Key_Right_15);


	//
	// Round 16 (in reverse order)
	//
	Final_Key_Left = Final_Key_Left_Permutation(DES_Key_Left_16); // permute both halves of key
	Final_Key_Right = Final_Key_Right_Permutation(DES_Key_Right_16);
	MangledText = Mangler(Text_Round_Left, Final_Key_Left, Final_Key_Right); // Mangle the left half (opposite as encrypt)
	New_Text_Round_Left = ManglerXOR(Text_Round_Right, MangledText);
	Text_Round_Right = Text_Round_Left;
	Text_Round_Left = New_Text_Round_Left;
	//cout << endl << Text_Round_Left << Text_Round_Right;


	//
	// Round 15 (in reverse order)
	//
	Final_Key_Left = Final_Key_Left_Permutation(DES_Key_Left_15); // permute both halves of key
	Final_Key_Right = Final_Key_Right_Permutation(DES_Key_Right_15);
	MangledText = Mangler(Text_Round_Left, Final_Key_Left, Final_Key_Right); // Mangle the left half (opposite as encrypt)
	New_Text_Round_Left = ManglerXOR(Text_Round_Right, MangledText);
	Text_Round_Right = Text_Round_Left;
	Text_Round_Left = New_Text_Round_Left;
	//cout << endl << Text_Round_Left << Text_Round_Right;


	//
	// Round 14 (in reverse order)
	//
	Final_Key_Left = Final_Key_Left_Permutation(DES_Key_Left_14); // permute both halves of key
	Final_Key_Right = Final_Key_Right_Permutation(DES_Key_Right_14);
	MangledText = Mangler(Text_Round_Left, Final_Key_Left, Final_Key_Right); // Mangle the left half (opposite as encrypt)
	New_Text_Round_Left = ManglerXOR(Text_Round_Right, MangledText);
	Text_Round_Right = Text_Round_Left;
	Text_Round_Left = New_Text_Round_Left;
	//cout << endl << Text_Round_Left << Text_Round_Right;


	//
	// Round 13 (in reverse order)
	//
	Final_Key_Left = Final_Key_Left_Permutation(DES_Key_Left_13); // permute both halves of key
	Final_Key_Right = Final_Key_Right_Permutation(DES_Key_Right_13);
	MangledText = Mangler(Text_Round_Left, Final_Key_Left, Final_Key_Right); // Mangle the left half (opposite as encrypt)
	New_Text_Round_Left = ManglerXOR(Text_Round_Right, MangledText);
	Text_Round_Right = Text_Round_Left;
	Text_Round_Left = New_Text_Round_Left;
	//cout << endl << Text_Round_Left << Text_Round_Right;


	//
	// Round 12 (in reverse order)
	//
	Final_Key_Left = Final_Key_Left_Permutation(DES_Key_Left_12); // permute both halves of key
	Final_Key_Right = Final_Key_Right_Permutation(DES_Key_Right_12);
	MangledText = Mangler(Text_Round_Left, Final_Key_Left, Final_Key_Right); // Mangle the left half (opposite as encrypt)
	New_Text_Round_Left = ManglerXOR(Text_Round_Right, MangledText);
	Text_Round_Right = Text_Round_Left;
	Text_Round_Left = New_Text_Round_Left;
	//cout << endl << Text_Round_Left << Text_Round_Right;


	//
	// Round 11 (in reverse order)
	//
	Final_Key_Left = Final_Key_Left_Permutation(DES_Key_Left_11); // permute both halves of key
	Final_Key_Right = Final_Key_Right_Permutation(DES_Key_Right_11);
	MangledText = Mangler(Text_Round_Left, Final_Key_Left, Final_Key_Right); // Mangle the left half (opposite as encrypt)
	New_Text_Round_Left = ManglerXOR(Text_Round_Right, MangledText);
	Text_Round_Right = Text_Round_Left;
	Text_Round_Left = New_Text_Round_Left;
	//cout << endl << Text_Round_Left << Text_Round_Right;


	//
	// Round 10 (in reverse order)
	//
	Final_Key_Left = Final_Key_Left_Permutation(DES_Key_Left_10); // permute both halves of key
	Final_Key_Right = Final_Key_Right_Permutation(DES_Key_Right_10);
	MangledText = Mangler(Text_Round_Left, Final_Key_Left, Final_Key_Right); // Mangle the left half (opposite as encrypt)
	New_Text_Round_Left = ManglerXOR(Text_Round_Right, MangledText);
	Text_Round_Right = Text_Round_Left;
	Text_Round_Left = New_Text_Round_Left;
	//cout << endl << Text_Round_Left << Text_Round_Right;


	//
	// Round 9 (in reverse order)
	//
	Final_Key_Left = Final_Key_Left_Permutation(DES_Key_Left_9); // permute both halves of key
	Final_Key_Right = Final_Key_Right_Permutation(DES_Key_Right_9);
	MangledText = Mangler(Text_Round_Left, Final_Key_Left, Final_Key_Right); // Mangle the left half (opposite as encrypt)
	New_Text_Round_Left = ManglerXOR(Text_Round_Right, MangledText);
	Text_Round_Right = Text_Round_Left;
	Text_Round_Left = New_Text_Round_Left;
	//cout << endl << Text_Round_Left << Text_Round_Right;


	//
	// Round 8 (in reverse order)
	//
	Final_Key_Left = Final_Key_Left_Permutation(DES_Key_Left_8); // permute both halves of key
	Final_Key_Right = Final_Key_Right_Permutation(DES_Key_Right_8);
	MangledText = Mangler(Text_Round_Left, Final_Key_Left, Final_Key_Right); // Mangle the left half (opposite as encrypt)
	New_Text_Round_Left = ManglerXOR(Text_Round_Right, MangledText);
	Text_Round_Right = Text_Round_Left;
	Text_Round_Left = New_Text_Round_Left;
	//cout << endl << Text_Round_Left << Text_Round_Right;


	//
	// Round 7 (in reverse order)
	//
	Final_Key_Left = Final_Key_Left_Permutation(DES_Key_Left_7); // permute both halves of key
	Final_Key_Right = Final_Key_Right_Permutation(DES_Key_Right_7);
	MangledText = Mangler(Text_Round_Left, Final_Key_Left, Final_Key_Right); // Mangle the left half (opposite as encrypt)
	New_Text_Round_Left = ManglerXOR(Text_Round_Right, MangledText);
	Text_Round_Right = Text_Round_Left;
	Text_Round_Left = New_Text_Round_Left;
	//cout << endl << Text_Round_Left << Text_Round_Right;


	//
	// Round 6 (in reverse order)
	//
	Final_Key_Left = Final_Key_Left_Permutation(DES_Key_Left_6); // permute both halves of key
	Final_Key_Right = Final_Key_Right_Permutation(DES_Key_Right_6);
	MangledText = Mangler(Text_Round_Left, Final_Key_Left, Final_Key_Right); // Mangle the left half (opposite as encrypt)
	New_Text_Round_Left = ManglerXOR(Text_Round_Right, MangledText);
	Text_Round_Right = Text_Round_Left;
	Text_Round_Left = New_Text_Round_Left;
	//cout << endl << Text_Round_Left << Text_Round_Right;


	//
	// Round 5 (in reverse order)
	//
	Final_Key_Left = Final_Key_Left_Permutation(DES_Key_Left_5); // permute both halves of key
	Final_Key_Right = Final_Key_Right_Permutation(DES_Key_Right_5);
	MangledText = Mangler(Text_Round_Left, Final_Key_Left, Final_Key_Right); // Mangle the left half (opposite as encrypt)
	New_Text_Round_Left = ManglerXOR(Text_Round_Right, MangledText);
	Text_Round_Right = Text_Round_Left;
	Text_Round_Left = New_Text_Round_Left;
	//cout << endl << Text_Round_Left << Text_Round_Right;


	//
	// Round 4 (in reverse order)
	//
	Final_Key_Left = Final_Key_Left_Permutation(DES_Key_Left_4); // permute both halves of key
	Final_Key_Right = Final_Key_Right_Permutation(DES_Key_Right_4);
	MangledText = Mangler(Text_Round_Left, Final_Key_Left, Final_Key_Right); // Mangle the left half (opposite as encrypt)
	New_Text_Round_Left = ManglerXOR(Text_Round_Right, MangledText);
	Text_Round_Right = Text_Round_Left;
	Text_Round_Left = New_Text_Round_Left;
	//cout << endl << Text_Round_Left << Text_Round_Right;


	//
	// Round 3 (in reverse order)
	//
	Final_Key_Left = Final_Key_Left_Permutation(DES_Key_Left_3); // permute both halves of key
	Final_Key_Right = Final_Key_Right_Permutation(DES_Key_Right_3);
	MangledText = Mangler(Text_Round_Left, Final_Key_Left, Final_Key_Right); // Mangle the left half (opposite as encrypt)
	New_Text_Round_Left = ManglerXOR(Text_Round_Right, MangledText);
	Text_Round_Right = Text_Round_Left;
	Text_Round_Left = New_Text_Round_Left;
	//cout << endl << Text_Round_Left << Text_Round_Right;


	//
	// Round 2 (in reverse order)
	//
	Final_Key_Left = Final_Key_Left_Permutation(DES_Key_Left_2); // permute both halves of key
	Final_Key_Right = Final_Key_Right_Permutation(DES_Key_Right_2);
	MangledText = Mangler(Text_Round_Left, Final_Key_Left, Final_Key_Right); // Mangle the left half (opposite as encrypt)
	New_Text_Round_Left = ManglerXOR(Text_Round_Right, MangledText);
	Text_Round_Right = Text_Round_Left;
	Text_Round_Left = New_Text_Round_Left;
	//cout << endl << Text_Round_Left << Text_Round_Right;


	//
	// Round 1 (in reverse order)
	//
	Final_Key_Left = Final_Key_Left_Permutation(DES_Key_Left_1); // permute both halves of key
	Final_Key_Right = Final_Key_Right_Permutation(DES_Key_Right_1);
	MangledText = Mangler(Text_Round_Left, Final_Key_Left, Final_Key_Right); // Mangle the left half (opposite as encrypt)
	New_Text_Round_Left = ManglerXOR(Text_Round_Right, MangledText);
	Text_Round_Right = Text_Round_Left;
	Text_Round_Left = New_Text_Round_Left;
	//cout << endl << Text_Round_Left << Text_Round_Right;


	//
	// End of Round 1
	//

	Text_Round_Left.append(Text_Round_Right); // join the two halves back together
	Text_Round_Left = FinalTextPermutation(Text_Round_Left); // final permutation
	Text_Round_Left = BinaryToHex(Text_Round_Left); // return the ciphertext to hex format


	return Text_Round_Left;
}


void EndOfProgram()
{
	int EndOfProgramVariable;
	cout << "To exit the program, press any key followed by the ENTER key: ";
	cin >> EndOfProgramVariable;
	cout << endl;
}


void InvalidResponseGiven()
{
	cout << "Invalid response given. Program will now terminate." << endl;
	cout << endl;
	EndOfProgram();
}


bool IsValidText(string TextToValidate)
{
	/* All texts must be:
	- 16 hex characters long (8 hex bytes)
	- In hexadecimal
	*/


	if (TextToValidate.length() != 16)
	{
		return false;
	}

	for (int charIndex = 0; charIndex < 16; charIndex++)
	{
		if (TextToValidate[charIndex] < 48) // less than 0
		{
			return false;
		}


		if ((TextToValidate[charIndex] > 57) && (TextToValidate[charIndex] < 65)) // more than 9 and less than A
		{
			return false;
		}


		if (TextToValidate[charIndex] > 70) // more than F
		{
			return false;
		}
	}


	return true;
}


bool IsValidKey(string KeyToValidate)
{
	/* All texts must be:
	- 14 hex characters long (7 hex bytes)
	- In hexadecimal
	*/


	if (KeyToValidate.length() != 14)
	{
		return false;
	}


	for (int charIndex = 0; charIndex < 14; charIndex++)
	{
		if (KeyToValidate[charIndex] < 48) // less than 0
		{
			return false;
		}


		if ((KeyToValidate[charIndex] > 57) && (KeyToValidate[charIndex] < 65)) // more than 9 and less than A
		{
			return false;
		}


		if (KeyToValidate[charIndex] > 70) // more than F
		{
			return false;
		}
	}


	return true;
}


int _tmain(int argc, _TCHAR* argv[])
{
	string CipherText;
	string PlainText;
	string DES_Key;
	string KeyboardInput;
	bool isEncrypt; // true means encrypt, false means decrypt


	cout << "JRV_DES by James Vaughan" << endl;
	cout << endl;
	cout << "Encrypt or decrypt?" << endl;
	cout << "Type \"encrypt\" or \"decrypt\" below: " << endl;
	cout << endl;
	cout << ">> ";
	cin >> KeyboardInput;
	cout << endl;


	if ((KeyboardInput != "encrypt") && (KeyboardInput != "decrypt"))
	{
		InvalidResponseGiven();
		return 0;
	}


	if (KeyboardInput == "encrypt")
	{
		isEncrypt = true;
	}


	if (KeyboardInput == "decrypt")
	{
		isEncrypt = false;
	}


	if (isEncrypt) // Encryption UI
	{
		cout << "The plaintext must be exactly 8 hex bytes, no spaces, all uppercase. " << endl;
		cout << "Please enter the plaintext to be encrypted below: " << endl;
		cout << endl;
		cout << "   ................" << endl;
		cout << ">> ";
		cin >> PlainText;
		cout << endl;


		if (!IsValidText(PlainText))
		{
			InvalidResponseGiven();
			return 0;
		}


		cout << "The key must be exactly 7 hex bytes, no spaces, all uppercase. " << endl;
		cout << "Please enter the DES key below: " << endl;
		cout << endl;
		cout << "   .............." << endl;
		cout << ">> ";
		cin >> DES_Key;
		cout << endl;


		if (!IsValidKey(DES_Key))
		{
			InvalidResponseGiven();
			return 0;
		}


		cout << "The generated ciphertext is shown below: " << endl;
		cout << endl;
		cout << DES_Encrypt(PlainText, DES_Key) << endl;
		cout << endl;
	}


	if (!isEncrypt) // Decryption UI
	{
		cout << "The ciphertext must be exactly 8 hex bytes, no spaces, all uppercase. " << endl;
		cout << "Please enter the ciphertext to be decrypted below: " << endl;
		cout << endl;
		cout << "   ................" << endl;
		cout << ">> ";
		cin >> CipherText;
		cout << endl;


		if (!IsValidText(CipherText))
		{
			InvalidResponseGiven();
			return 0;
		}


		cout << "The key must be exactly 7 hex bytes, no spaces, all uppercase. " << endl;
		cout << "Please enter the DES key below: " << endl;
		cout << endl;
		cout << "   .............." << endl;
		cout << ">> ";
		cin >> DES_Key;
		cout << endl;


		if (!IsValidKey(DES_Key))
		{
			InvalidResponseGiven();
			return 0;
		}


		cout << "The generated plaintext is shown below: " << endl;
		cout << endl;
		cout << DES_Decrypt(CipherText, DES_Key) << endl;
		cout << endl;
	}

	EndOfProgram();
	return 0;
}
