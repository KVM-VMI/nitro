#include <Windows.h>


int main()
{
	LPCTSTR path = L"foobar.txt";
	DWORD	desired_access = FILE_APPEND_DATA;
	DWORD	share_mode = NULL;
	LPSECURITY_ATTRIBUTES security_attributes = NULL;
	DWORD	creation_disposition = CREATE_ALWAYS;
	DWORD	flags_and_attributes = FILE_ATTRIBUTE_NORMAL;
	HANDLE	template_file = NULL;

	HANDLE f = CreateFile(path,
		desired_access,				// desired access
		share_mode,						// share mode
		security_attributes,						// security attributes
		creation_disposition,				// creation disposition
		flags_and_attributes,
		template_file
	);

	return 0;
}

