
#define _CRT_SECURE_NO_WARNINGS

#include <WinSock2.h>
#include <Windows.h>
#include <http.h>
#include <sddl.h>

#include <stdlib.h>
#include <stdio.h>

#define URL L"http://localhost:2001/"

void version1( void );
void version2( void );
static void print_token_sid( HANDLE token );
static DWORD WINAPI ServerThread( void *arg );
static ULONG InitVersion2( void );
static ULONG CloseVersion2( void );

static HANDLE stop_event;
static HTTP_SERVER_SESSION_ID sessid;
static HANDLE hreq;

int main( int argc, char **argv ) {
	HANDLE thread;
	DWORD ThreadId;
	ULONG sts;

	// start by initializing the http stuff
	sts = InitVersion2();
	if( sts ) return 0;

	// create the stop event 
	stop_event = CreateEvent( NULL, FALSE, FALSE, NULL );

	// launch the server thread
	thread = CreateThread( NULL, 0, ServerThread, NULL, 0, &ThreadId );

	// await a keypress
	getchar();

	// close things down
	SetEvent( stop_event );
	sts = CloseVersion2();
	WaitForSingleObject( thread, INFINITE );

	return 0;
}

static ULONG InitVersion2( void ) {
	ULONG sts;
	HTTPAPI_VERSION version = HTTPAPI_VERSION_2;
	HTTP_SERVER_AUTHENTICATION_INFO authinfo;
	HTTP_URL_GROUP_ID urlgroupid;
	wchar_t url[] = URL;
	HTTP_BINDING_INFO binding;

	sts = HttpInitialize( version, HTTP_INITIALIZE_SERVER, NULL );
	if( sts ) {
		printf( "Failed to initialize - %d\n", sts );
		return sts;
	}

	sts = HttpCreateServerSession( version, &sessid, 0 );
	if( sts ) {
		printf( "Failed to create session - %d\n", sts );
		return sts;
	}

	// ----------------------- create a server session ------------------------------ 

	// set to use authentication
	ZeroMemory( &authinfo, sizeof(authinfo) );
	authinfo.AuthSchemes = HTTP_AUTH_ENABLE_NTLM; //HTTP_AUTH_ENABLE_BASIC; //HTTP_AUTH_ENABLE_NEGOTIATE;
	authinfo.Flags.Present = 1;
	sts = HttpSetServerSessionProperty( sessid, HttpServerAuthenticationProperty, &authinfo, sizeof(authinfo) );
	if( sts ) {
		printf( "Failed to set auth info - %d\n", sts );
		return sts;
	}

	// ----------------------------- create url gorup -------------------------------

	sts = HttpCreateUrlGroup( sessid, &urlgroupid, 0 );
	if( sts ) {
		printf( "Failed to create url group - %d\n", sts );
		return sts;
	}

	// add url to gfreoup	
	sts = HttpAddUrlToUrlGroup( urlgroupid, url, NULL, 0 );
	if( sts ) {
		printf( "Failed to add url to group - %d\n", sts );
		return sts;
	}

	// ------------------- create a request queue --------------------------

	sts = HttpCreateRequestQueue( version, NULL, NULL, 0, &hreq );
	if( sts ) {
		printf( "Failed to create request queue - %d\n", sts );
		return sts;
	}

	// bind the url group to the request queue
	ZeroMemory( &binding, sizeof(binding) );
	binding.RequestQueueHandle = hreq;
	binding.Flags.Present = 1;
	sts = HttpSetUrlGroupProperty( urlgroupid, HttpServerBindingProperty, &binding, sizeof(binding) );
	if( sts ) {
		printf( "Failed to bind url group to the request queue - %d\n", sts );
		return sts;
	}

	return 0;
}

static ULONG CloseVersion2( void ) {
	ULONG sts;

	sts = HttpCloseRequestQueue ( hreq );
	
	sts = HttpCloseServerSession( sessid );
	if( sts ) {
		printf( "Failed to close session - %d\n", sts);
		return sts;
	}

	sts = HttpTerminate( HTTP_INITIALIZE_SERVER, NULL );
	return sts;
}

static DWORD WINAPI ServerThread( void *arg ) {
	
	while( WaitForSingleObject( stop_event, 0 ) != WAIT_OBJECT_0 ) {
		version2();
	}

	return 0;
}

void version2( void ) {
	ULONG sts;	
	HTTP_REQUEST_ID reqid = 0;
	HTTP_REQUEST *reqbuffer;
	ULONG count, nbytes;
	HTTP_RESPONSE *resbuffer;
	char *buffer;
	HTTP_REQUEST_AUTH_INFO *ainfo;
	int i;
	HTTP_DATA_CHUNK datachunk;
	char buff[1024], username[200];
	DWORD d;

	
	// ------------------------------- wait for a request to come in --------------


	// wait for a new request by setting the reqid to null
	HTTP_SET_NULL_ID( &reqid );

	// allocate request buffer
	count = sizeof(HTTP_REQUEST) + (4*1024);
	reqbuffer = (HTTP_REQUEST *)calloc( 1, count );
	nbytes = 0;
	sts = HttpReceiveHttpRequest( hreq, reqid, HTTP_RECEIVE_REQUEST_FLAG_COPY_BODY, reqbuffer, count, &nbytes, NULL );
	if( sts ) {
		printf( "Failed to receive request - %d\n", sts );
		goto done;
	}

	printf( "Established a connection\n" );

	ZeroMemory( buff, sizeof(buff) );	

	strcpy( buff, inet_ntoa( ((struct sockaddr_in *)reqbuffer->Address.pRemoteAddress)->sin_addr ) );
	//wcstombs( buff, reqbuffer->CookedUrl.pHost, reqbuffer->CookedUrl.HostLength );

	// ----------------- get the authentication information ----------------

	ainfo = NULL;
	for( i = 0; i < reqbuffer->RequestInfoCount; i++ ) {		
		if( reqbuffer->pRequestInfo[i].InfoType == HttpRequestInfoTypeAuth ) {
			ainfo = (HTTP_REQUEST_AUTH_INFO *)reqbuffer->pRequestInfo[i].pInfo;		
			break;
		}
	}

	if( ainfo && ainfo->AuthStatus == HttpAuthStatusSuccess ) {		
		printf( "(%s) Authentication success: ", buff );
		ImpersonateLoggedOnUser( ainfo->AccessToken );
		//print_token_sid( ainfo->AccessToken );
		d = 200;
		GetUserNameA( username, &d );
		RevertToSelf();

		printf( "User: %s\n", username );


		reqid = reqbuffer->RequestId;

		// --------------------- get the response -------------------------
		count = 2*1024;
		buffer = (char *)calloc( 1, count );
		nbytes = 0;
		sts = HttpReceiveRequestEntityBody( hreq, reqid, 0, buffer, count, &nbytes, NULL );
		if( sts ) {
			printf( "Failed to get request body - %d\n", sts );
		}

		printf( "(%s) Body: %s\n", buff, buffer );
		free( buffer );
	
		// ------------------------ send the response ------------------------------------

		count = sizeof(HTTP_RESPONSE) + 2*1024;
		resbuffer = (HTTP_RESPONSE *)calloc( 1, count );
		resbuffer->EntityChunkCount = 1;
		ZeroMemory( &datachunk, sizeof(datachunk) );

		resbuffer->StatusCode = 200;

		resbuffer->pEntityChunks = &datachunk;
		datachunk.DataChunkType = HttpDataChunkFromMemory;
		datachunk.FromMemory.pBuffer = calloc( 1, 1024 );
		sprintf_s( (char *)datachunk.FromMemory.pBuffer, 1024, "Hello %s", username );
		datachunk.FromMemory.BufferLength = strlen( (char *)datachunk.FromMemory.pBuffer );
		sts = HttpSendHttpResponse( hreq, reqbuffer->RequestId, 0, resbuffer, NULL, &nbytes, NULL, 0, NULL, NULL );
		if( sts ) {
			printf( "Failed to send response - %d\n", sts );
			goto done;
		}

		free( datachunk.FromMemory.pBuffer );
		free( resbuffer );
		free( reqbuffer );

	} else {
		printf( "(%s) Authentication failed\n", buff );
		count = sizeof(HTTP_RESPONSE) + 2*1024;
		resbuffer = (HTTP_RESPONSE *)calloc( 1, count );
		resbuffer->EntityChunkCount = 1;
		ZeroMemory( &datachunk, sizeof(datachunk) );
		resbuffer->StatusCode = 401;
		resbuffer->pEntityChunks = &datachunk;
		datachunk.DataChunkType = HttpDataChunkFromMemory;
		datachunk.FromMemory.pBuffer = calloc( 1, 1024 );
		sprintf_s( (char *)datachunk.FromMemory.pBuffer, 1024, "!!!AUTHFAILED!!!" );
		datachunk.FromMemory.BufferLength = strlen( (char *)datachunk.FromMemory.pBuffer ); //1024;
		sts = HttpSendHttpResponse( hreq, reqbuffer->RequestId, 0, resbuffer, NULL, &nbytes, NULL, 0, NULL, NULL );
		if( sts ) {
			printf( "Failed to send response - %d\n", sts );
			goto done;
		}

		free( datachunk.FromMemory.pBuffer );
		free( resbuffer );
		free( reqbuffer );
	}
	

done:

	
	 return;
}

static void print_token_sid( HANDLE token ) {
	LPSTR sidstr;
	TOKEN_USER *tuser;
	BOOL b;
	DWORD length;
	DWORD sts;

	tuser = (TOKEN_USER *)calloc( 1, 1024 );
	b = GetTokenInformation( token, TokenUser, tuser, 1024, &length );
	if( !b ) {
		sts = GetLastError();
		printf( "Failed to get token information - %d\n", sts );
		return;
	}

	b = ConvertSidToStringSidA( tuser->User.Sid, &sidstr );
	if( !b ) {
		sts = GetLastError();
		printf( "Failed to get token SID - %d\n", sts );
		return;
	}
	
	printf( "%s\n", sidstr );

	LocalFree( sidstr );
	free( tuser );

}

