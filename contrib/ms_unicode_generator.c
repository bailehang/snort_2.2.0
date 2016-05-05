/**
**  @file       ms_unicode_generator.c
**              Copyright (C) 2003, Daniel Roelker
**  
**  @author     Daniel Roelker <droelker@sourcefire.com>
**  
**  @brief      Program for dumping unicode codepoints that map to ASCII
**              chars for each installed and valid codepage.
**  
**  This program is for dumping installed unicode codepage codepoints that
**  map to ASCII chars.  This file is used for IDS systems to correctly
**  decode unicode encoded URI requests.
**  
**  This program also shows the Microsoft OS version (we don't care about
**  systems that aren't NT-like) and the OEM and ASCII codepages.  It
**  appears that IIS uses the ASCII default codepage on each system, so
**  you should use the ACP when configuring your IDS.
**  
**  NOTES:
**    - Initial development.  DJR
*/
#include <windows.h>
#include <stdio.h>

/**
**  NAME
**    CovertCodepoint::
*/
/**
**  Receive a unicodecodepoint and convert to multibyte.  If the multibyte
**  is really ASCII then return the codepoint mapping.
**  
**  There is really not much to this function except that we have to check
**  multiple return parameters from the function.
**  
**  @param CP           the codepage to iterate through
**  @param UnicodeChar  the codepoint to check
**  
**  @return UCHAR
**  
**  @retval NULL   no valid ASCII mapping to codepoint
**  @retval !NULL  valid ASCII mapping to codepoint
*/
static UCHAR *ConvertCodepoint(UINT CP, wchar_t UnicodeChar)
{
    BOOL          UsedDefaultChar;
    static char   AsciiString;
    int           iRet;

    /*
    **  We are only interested in the multibyte conversion to one byte values,
    **  so we only pass in a buffer of length one.
    */ 
    iRet = WideCharToMultiByte(CP, 0, &UnicodeChar, 1, &AsciiString, 1, NULL,
                               &UsedDefaultChar);

    /*
    **  The return value (iRet) tells us how many chars have been put in the
    **  AsciiString, so we only look for the Strings that are one char
    **  because we are only looking for ASCII chars.
    **
    **  We check the UsedDefaultChar becasue if it is TRUE this means that
    **  the routine had no codepoint mapping for this char.  We are not
    **  interested in those codepoints.
    **
    **  We check that the AsciiString and the UnicodeChar are not the same
    **  char, since we check the ASCII mappings for anything weird.
    **
    **  Last, we check that the AsciiString is actually ASCII, so we don't
    **  get any of the Non-ASCII single byte chars.
    */
    if((iRet == 1) && (UsedDefaultChar == FALSE) && ((UCHAR)AsciiString !=
       (UCHAR)UnicodeChar) && ((UCHAR)AsciiString < 0x80))
    {
        return (UCHAR *)&AsciiString;
    }
    
    return NULL;
}

/*
**  NAME
**    PrintStuff::
*/
/**
**  This is the callback function for enumerating the installed codepages.
**
**  We found out that just because it is installed doesn't mean it's a
**  VALID codepage.  So after we get the codepage number, we check to
**  make sure that it is valid.
**
**  We then print out the Windows information about this codepage, like
**  the english name, and then iterate through the codepoints and print
**  out the ones that map to ascii characters.
**
**  @param lpCodePageString pointer to TSTR.
**  
**  @return BOOL
**
**  @retval TRUE   continue enumerating codepages
**  @retval FALSE  stop enumerating codepages
*/   
static BOOL CALLBACK PrintStuff(LPTSTR lpCodePageString)
{
    UINT CodePage;
    CPINFOEX CPInfoEx;
    UCHAR *AsciiChar;
    UINT uCtr;

    CodePage = (UINT)atoi(lpCodePageString);
    
    if(!IsValidCodePage(CodePage))
    {
        printf("#INVALID CODEPAGE: %u\n\n", CodePage);
        return TRUE;
    }

    if(GetCPInfoEx(CodePage, 0, &CPInfoEx))
    {
        printf("%s\n", CPInfoEx.CodePageName);
    }

    /*
    **  We iterate through all the one byte values because some of the
    **  values were mapped to other ASCII values.  c1 => 25 or something
    **  like that.
    */
    for(uCtr = 0x00; uCtr <= 0xFFFF; uCtr++)
    {
        if((AsciiChar = ConvertCodepoint(CodePage, (wchar_t)uCtr)) != NULL)
            printf("%.4x:%.2x ", uCtr, *AsciiChar);
    }

    printf("\n\n");

    return TRUE;
}

int main(int argc, char* argv[])
{
    UINT  CodePage;
    OSVERSIONINFO VersionInfo;

    VersionInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

    /*
    **  Let's get the version of Windows.
    */
    if(GetVersionEx(&VersionInfo))
    {
        if(VersionInfo.dwPlatformId == VER_PLATFORM_WIN32_NT)
        {
            printf("# Windows Version: %lu.%.2lu.%lu\n",
                VersionInfo.dwMajorVersion, VersionInfo.dwMinorVersion,
                VersionInfo.dwBuildNumber);
        }
        else
        {
            printf("# Not Win32 NT version.\n");
            return 0;
        }

        /*
        **  We get the OEM codepage for this Windows installation
        */
        CodePage = GetOEMCP();
        printf("# OEM codepage: %u\n", CodePage);

        /*
        **  We get the ANSII codepage for this Windows installation
        */
        CodePage = GetACP();
        printf("# ACP codepage: %u\n\n", CodePage);

        /*
        **  Iterate through the INSTALLED codepages on this system
        */
        printf("# INSTALLED CODEPAGES\n");
        EnumSystemCodePages(PrintStuff, CP_INSTALLED);
    }

    return 0;
}
