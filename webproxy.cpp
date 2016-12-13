#ifndef UNICODE
#define UNICODE
#endif

#define WIN32_LEAN_AND_MEAN
#include <stdlib.h>
#include <io.h>
#include <winsock2.h>
#include <Ws2tcpip.h>
#include <string>
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <thread>
#include "md5.h"
#include <mutex>
#include <vector>

// Link with ws2_32.lib
#pragma comment(lib, "Ws2_32.lib")

#define DESIRED_WINSOCK_VERSION 0x0202
#define MINIMUM_WINSOCK_VERSION 0x0001
#define MAX_SOCKET_NUMBER 1000
#define MAXBUF 500000
#define IMAGEBUF 1000000
#define NUMBER_OF_THREAD 30
using namespace std;

static string cache_dir = "./cache/";
static string cache_list_dir = "./cache/list/";
static string option = "";
static string filterWords = "";
static string changeWords="";
int socket_enable[MAX_SOCKET_NUMBER];
int DATA_CHANGE_FLAG=0;
HANDLE console;
mutex mtx;

static int extractContentLength(char * data) {
	string str = data;
	char * get_index;
	char * end_index;
	int offset = 0;
	if ((get_index = strstr(data, "Content-Length:")) != NULL)
	{
		get_index += sizeof("Content-Length:");
		end_index = get_index;
		for (int i = 0; i < 10; i++)
		{
			end_index++;
			offset++;
			if (*end_index == '\r'&&*(end_index + 1) == '\n')
			{
				break;
			}
		}
		char tmp[10];
		memcpy(tmp, get_index, offset);
		tmp[offset] = '\0';
		int ret = atoi(tmp);
		return ret;
	}
	else
		return -1;
}
/*change Packet data static length*/
static BOOL changeGetData(char * ppacket, int &packet_size, string  original, int original_size, string changed, int changed_size)
{
	int offset = 0;
	int find_index = 0;
	int change_size = changed_size-original_size;

	while (offset + original_size<packet_size)
	{
		for (int j = 0; j < original_size; j++)
		{
			if (*(ppacket + offset + j) == original[j])
			{
				if (j == original_size - 1)
				{
					for (int k = 0; k < changed_size; k++)
					{
						*(ppacket + offset + k) = changed[k];
					}
					return TRUE;
				}
			}
			else
				break;
		}
		offset++;
	}
	return FALSE;
}

/*change data variable length*/
static char * changeData(char * ppacket, int &packet_size, string  original, int original_size, string changed, int changed_size)
{
	
	int original_packet_size = packet_size;
	ppacket[packet_size] = '\0';
	int change_count = 0;
	char * find_index = NULL;
	find_index = ppacket;
	while ((find_index = strstr(find_index, original.c_str())) != NULL)
	{
		find_index++;
		change_count++;
	}

	int change_size = (changed_size - original_size)*change_count;
	int origin_content_size = extractContentLength(ppacket);
	if (origin_content_size == -1) //Content_length 가 없을 때 
	{
		char * tmp;
		if ((tmp = strstr(ppacket, original.c_str())) != NULL)
		{
			for (int i = 0; i < changed.length(); i++)
				*&(tmp[i]) = changed[i];
			return ppacket;
		}
		else
			return NULL;
	}
	int changed_content_size = origin_content_size + change_size;
	packet_size += change_size;

	char * newpacket = (char*)malloc(sizeof(char)*packet_size);

	char* content_length_p;
	char * old_tmp = ppacket;
	char * prev_tmp=ppacket;
	char * new_tmp= newpacket;
	char* after_content_length_p=NULL;
	char* start_content_length_p=NULL;
	int remain_size=0;
	string newString = "";
	int new_offset = 0;
	if ((old_tmp = strstr(ppacket, "Content-Length: ")) != NULL)
	{
		old_tmp += sizeof("Content-Length: ")-1;
		new_offset = old_tmp - ppacket;
		memcpy(new_tmp, ppacket, new_offset);
		new_tmp += new_offset;
		string size = to_string(changed_content_size); //content length 쓰기
		int end = size.length();
		for (int i = 0; i < end; i++)
		{
			*new_tmp = size.at(i);
			new_tmp++;
		}
		if ((old_tmp = strstr(old_tmp, "\r\n")) != NULL)
		{
			prev_tmp = old_tmp;
			while ((old_tmp = strstr(old_tmp, original.c_str())) != NULL)
			{
				new_offset = old_tmp - prev_tmp;
				memcpy(new_tmp, prev_tmp, new_offset);
				new_tmp += new_offset;
				for (int i = 0; i < changed.length(); i++)
				{
					*new_tmp = changed.at(i);
					new_tmp++;
				}
				old_tmp+=original.length();
				prev_tmp = old_tmp;
			}
			int last = 0;
			while (prev_tmp != &ppacket[original_packet_size])
			{
				*new_tmp = *(prev_tmp);
				new_tmp++;
				prev_tmp++;
			}
		}

	}
	newpacket[packet_size] = '\0';
	return newpacket;
}

static int isImageRequest(char * data) {
	string str = data;
	char * get_index;
	if ((get_index = strstr(data, "GET ")) != NULL)
	{
		string image_str = get_index;
		const char * image_index;

		if ((image_index = strstr(image_str.c_str(), ".jpg")) != NULL) {
			return 1;
		}
		else if ((image_index = strstr(image_str.c_str(), ".jpeg")) != NULL)
		{
			return 2;
		}
		else if ((image_index = strstr(image_str.c_str(), ".png")) != NULL)
		{
			return 3;
		}
		else
			return -1;
	}
	else
		return -1;
}
static int isImageResponse(char * data) {
	string str = data;
	char * get_index;
	if ((get_index = strstr(data, "Content-Type: image/jpeg")) != NULL)
	{
		return 1;
	}
	else if ((get_index = strstr(data, "Content-Type: image/png")) != NULL)
	{
		return 2;
	}
	else
		return -1;
}


static string extractURI(char * data) {
	string str = data;
	char * get_index;
	if ((get_index = strstr(data, "GET ")) != NULL) {
		string uri_str = get_index + sizeof("GET");
		const char * image_index;
		if ((image_index = strstr(uri_str.c_str(), ".jpg")) != NULL)
		{
			string image_after = image_index;
			return uri_str.substr(0, uri_str.size() - image_after.size() + sizeof(".jpg"));
		}
		else if ((image_index = strstr(uri_str.c_str(), ".png")) != NULL)
		{
			string image_after = image_index;
			return uri_str.substr(0, uri_str.size() - image_after.size() + sizeof(".png"));
		}
		else if ((image_index = strstr(uri_str.c_str(), ".jpeg")) != NULL)
		{
			string image_after = image_index;
			return uri_str.substr(0, uri_str.size() - image_after.size() + sizeof(".jpeg"));
		}

	}
	else
		return NULL;
}
static string stringhash(string input)
{
	MD5 md5(input);
	return md5.hexdigest();
}
in_addr host2ip_addr(char * from_client_buff) {
	/*host name parsing*/
	string hostname;
	size_t index;
	char * hostpart;
	if ((hostpart = strstr(from_client_buff, "Host:")) != NULL)
	{
		hostname = hostpart + 6;
		index = hostname.find('\r', 0);
		hostname = hostname.substr(0, index);
	}
	else
	{
		//	puts(from_client_buff);
		printf("No host information\n");
	}

	/*hostname -> ip*/
	struct hostent *ent = gethostbyname(hostname.c_str());
	if (ent != NULL)
	{
		struct in_addr ip_addr = *(struct in_addr *)(ent->h_addr);
		return ip_addr;
	}
	else
	{
		puts(hostname.c_str());
		printf("Host -> Ip Failed!\n");
		struct in_addr ip_addr = *(struct in_addr *)(ent->h_addr);
		return ip_addr;
	}
}

int cacheCheck(string hash)
{
	_finddata_t fd;
	long handle;
	int result = 1;
	int exist = 0;
	string file_path = "";
	file_path.append(cache_dir + hash);
	const char * dir = file_path.c_str();
	handle = _findfirst(dir, &fd);
	if (handle == -1)
	{
		printf("There were no files.\n");
		return -1;
	}
	while (result != -1)
	{
		string filename = fd.name;
		if (!filename.compare(hash))
		{
			exist = 1;
			ifstream imagefile(file_path, std::ifstream::ate | std::ifstream::binary);
			int file_size = imagefile.tellg();
			return file_size;
			_findclose(handle);
		}
		result = _findnext(handle, &fd);
	}
	_findclose(handle);
	return -1;
}

char * imageReplyPacketMake(int &http_size, int image_type, int length) {
	char* buff;
	string ok = "HTTP/1.0 200 Ok\r\n";
	string content_type = "Content - Type: image / ";
	string content_length = "Content - Length : ";
	if (image_type == 1)
		content_type += "jpg";
	if (image_type == 2)
		content_type += "png";
	if (image_type == 3)
		content_type += "jpeg";
	content_type += "\r\n";
	content_length += to_string(length);
	content_length += "\r\n\r\n";
	string full = ok + content_type + content_length;
	int header_size = full.length();
	http_size = header_size;
	buff = (char*)malloc(sizeof(char)*(header_size+length));
	for (int i = 0; i < header_size; i++)
	{
		buff[i] = full.at(i);
	}
	return buff;
}

int isContainWord(char * ppacket, string original)
{
	if (strstr(ppacket, original.c_str()) == NULL)
		return -1;
	else
		return 1;
}

void Sequence(SOCKET m_client_sock,int client_id) {

	struct sockaddr_in client_addr, web_server_addr;
	SOCKET m_server_sock;
	time_t start_time = time(NULL);
	int clen;
	int from_client_recv_len;
	char from_client_buff[MAXBUF];
	char from_webserver_buff[MAXBUF];
	char * cache=NULL;
	char * buff_p;
	int image_size = 0;
	int image_flag = 0;
	int kind_of_image = 0;
	int image_header_check = 0;
	string image_hash = "";
	int cache_image_exist = 0;
	int cache_file_size = 0;

	while (1)
	{
		//mtx.lock();
	//	cout << "# " << client_id<< " From client waiting packet..." << endl;
	//	mtx.unlock();
		from_client_recv_len = recv(m_client_sock, from_client_buff, MAXBUF - 1, 0);
	//	mtx.lock();
	//	cout << "# " << client_id << " From client recieving packet..." << endl;
	//	mtx.unlock();
		if (from_client_recv_len > 0)
		{
			from_client_buff[from_client_recv_len] = '\0';
			if (from_client_buff[0] == 'C') // CONNECT METHOD 제외
			{
			//	mtx.lock();
			//	cout << "# " << client_id << " From client waiting packet..." << endl;
			//	mtx.unlock();
				continue;
			}
			if (DATA_CHANGE_FLAG) {
				changeGetData(from_client_buff, from_client_recv_len, "gzip,", sizeof("gzip,") - 1, "    ", sizeof("    ") - 1);
			}

			/*이미지 요청 확인*/
			if ((kind_of_image=isImageRequest(from_client_buff))>0) {
				string file_name = extractURI(from_client_buff);
				image_hash = stringhash(file_name);
				if (kind_of_image == 1)
					image_hash += ".jpg";
				else if (kind_of_image == 2)
					image_hash += ".jpeg";
				else if (kind_of_image == 3)
					image_hash += ".png";

				// hash name으로 cache 확인
				if ((cache_file_size=cacheCheck(image_hash)) >0)
				{
					cache_image_exist = 1;
				}
				if (cache_image_exist == 1)
				{
					int send_status; 
					//content size 확인
					//int content_legnth = extractContentLength(from_webserver_buff);
					int http_header_size = 0;
					char * p ;
					cache= imageReplyPacketMake(http_header_size, kind_of_image, cache_file_size);
					p = cache;
					p += http_header_size;
					ifstream imagefile(cache_dir + image_hash,ios::binary);
					imagefile.read(p, cache_file_size);
					if ((send_status = send(m_client_sock, cache, cache_file_size+ http_header_size, 0)) >0)
					{
						ofstream tmp("tmp", ios::binary);
						tmp.write(cache, cache_file_size + http_header_size);
						tmp.close();
						shutdown(m_client_sock, SD_BOTH);
						closesocket(m_client_sock);
						free(cache);
						return;
					}
				}
				image_flag = 1;
			}
		//	mtx.lock();
		//	cout << "# " << client_id << " Client packet recieved! bytes : " << from_client_recv_len << endl << endl;
		//	mtx.unlock();
			//	puts(from_client_buff);
			break;
		}
		else if (from_client_recv_len == -1)
		{
		
			closesocket(m_client_sock);
		//	mtx.lock();
		//	cout << "# " << client_id << " client -> web server (Request Failed " << from_client_recv_len << endl << endl;
		//	cout << "# " << client_id << " Terminated!" << endl;
		//	mtx.unlock();
			return;
		}
		else if (from_client_recv_len == 0)
		{
		//	mtx.lock();
		//	printf("# %d Client disconnected!\n", client_id);
		//	cout << "# " << client_id << " Terminated!" << endl;
		//	mtx.unlock();
			closesocket(m_client_sock);
			return;
		}
	}

	struct in_addr ip_addr = host2ip_addr(from_client_buff);
	m_server_sock = socket(PF_INET, SOCK_STREAM, 0);
	if (m_server_sock == INVALID_SOCKET)
		printf("socket() error");
	memset(&web_server_addr, 0, sizeof(web_server_addr));
	web_server_addr.sin_family = AF_INET;
	web_server_addr.sin_addr = ip_addr;
	web_server_addr.sin_port = htons(80);

	/*웹서버와 연결*/
	if (connect(m_server_sock, (SOCKADDR*)&web_server_addr, sizeof(web_server_addr)) == SOCKET_ERROR)//입력한 주소로 접속
	{
		printf("Web server connected Error\n");
	}
	else
	{
	//	mtx.lock();
	//	cout << "# " << client_id << " Web server connected!" << endl;
	//	mtx.unlock();
		/*데이터 보내기*/
		int to_webserver_send_len;
		if ((to_webserver_send_len = send(m_server_sock, from_client_buff, from_client_recv_len, 0)) != SOCKET_ERROR)
		{
		//	mtx.lock();
		//	cout << "# " << client_id;
		//	printf(" To webserver sended bytes : %d ", to_webserver_send_len);
			int from_web_recv_len=0;
			int image_save = 0;
		//	cout << "# " << client_id;
		//	cout << " Waiting packet from webserver...\n" << endl;
		//	mtx.unlock();
			while((from_web_recv_len = recv(m_server_sock, from_webserver_buff, MAXBUF - 1, 0))>0)
			{
				mtx.lock();
				cout << "# " << client_id;
				printf(" Bytes received from webserver: %d\n", from_web_recv_len);
				mtx.unlock();

				/*캐쉬가 없어 이미지 캐싱하기*/
				if (image_flag == 1)
				{
					from_webserver_buff[from_web_recv_len] = '\0';
					if (cache_image_exist == 0)
					{
						if (image_save == 1)
						{
							mtx.lock();
							ofstream imagefile(cache_dir + image_hash, ios::binary);
							imagefile.write(from_webserver_buff, from_web_recv_len);
							imagefile.close();
							mtx.unlock();
							if (image_size > MAXBUF) {
								cout << "image too large ! " << endl;
							}
						}
						/*HTTP 헤더 패킷*/
						image_save = 1;
					}
				}
				
				char* newPacket= from_webserver_buff;
				int isContain = 0;
				if (DATA_CHANGE_FLAG)
				{
					if ((isContain=isContainWord(newPacket, filterWords))==1)
					{
						newPacket = changeData(from_webserver_buff, from_web_recv_len,filterWords, filterWords.length(), changeWords, changeWords.length());
						if (newPacket == NULL)
							newPacket = from_webserver_buff;
					}
				}

				int send_status;
				if ((send_status = send(m_client_sock, newPacket, from_web_recv_len, 0)) >0)
				{

				//	mtx.lock();
				//	cout << "# " << client_id;
				//	printf(" Bytes sended to client: %d\n", send_status);
				//	mtx.unlock();
				}
				else
				{
				//	mtx.lock();
				//	cout << "# " << client_id;
				//	printf(" Bytes sended to client: %d  Failed!\n", send_status);
				//	cout << webServerConnOk << endl;
				//	mtx.unlock();

					shutdown(m_client_sock, SD_BOTH);
					closesocket(m_client_sock);
					break;
				}
			} 
			/*from web server recv done*/
			if (from_web_recv_len == 0)
			{
				mtx.lock();
				cout << "# " << client_id;
				printf(" Bytes received from webserver: %d Connection closed \n", from_web_recv_len);
				cout << "# " << client_id << " Terminated!" << endl;
				mtx.unlock();
				return;
			}
			else if(from_client_recv_len==-1)
			{
				mtx.lock();
				cout << "# " << client_id;
				printf(" recv failed with error: %d\n", WSAGetLastError());
				cout << "# " << client_id << " Terminated!" << endl;
				mtx.unlock();
				return;
			}
		}
	}
	// 서버 소켓을 닫음
	shutdown(m_server_sock, SD_BOTH);
	closesocket(m_server_sock);
	shutdown(m_client_sock, SD_BOTH);
	closesocket(m_client_sock);
	mtx.lock();
	cout << "# " << client_id << " Terminated!" << endl;
	socket_enable[client_id] = 1;
	mtx.unlock();
	return;
}

int checkSocket()
{
	int full = 1;
	for (int i = 0; i < MAX_SOCKET_NUMBER; i++)
	{
		if (socket_enable[i] == 1)
		{
			socket_enable[i] = 0;
			full = 0;
			return i;
		}
	}
	if (full)
	{
		cout << "No available socket is remained" << endl;
		return -1;
	}
}


int main(int argc, char *argv[])
{
	std::string current_exec_name = argv[0]; // Name of the current exec program
	std::string first_arge;
	std::vector<std::string> all_args;

	if (argc > 3) {

		first_arge = argv[1];
		all_args.assign(argv + 1, argv + argc);
	}
	option = all_args.at(0);
	if (!option.compare("-f"))
	{
		DATA_CHANGE_FLAG = 1;
		filterWords = all_args.at(1);
		changeWords = all_args.at(2);
	}

	SOCKET m_client_sock[MAX_SOCKET_NUMBER];
	for (int i = 0; i < MAX_SOCKET_NUMBER; i++)
		m_client_sock[i] = INVALID_SOCKET;
	SOCKET m_listen_sock = INVALID_SOCKET; // 소켓 디스크립트 정의
	WSADATA wsadata;
	struct sockaddr_in client_addr, proxy_server_addr;
	int nSockOpt;
	int status;
	ofstream log("log.txt");
	int socketbuffsize;
	int webServerConnOk = 0;
	int ClientConnOk = 0;
	int clientSendAll = 0;

	int clen;
	char from_client_buff[MAXBUF];
	char from_webserver_buff[MAXBUF];
	int sock_cnt = 0;

	for (int i = 0; i < MAX_SOCKET_NUMBER; i++)
		socket_enable[i] = 1;

	// 소켓을 초기화 
	if (!WSAStartup(DESIRED_WINSOCK_VERSION, &wsadata)) {
		if (wsadata.wVersion < MINIMUM_WINSOCK_VERSION) {
			WSACleanup();
			exit(1);
		}
	}

	// 서버 소켓 생성
	m_listen_sock = socket(AF_INET, SOCK_STREAM, 0);
	if (m_listen_sock == INVALID_SOCKET) {
		printf("socket error : ");
		WSACleanup();
		exit(1);
	}

	// 주소 구조체에 주소 지정
	memset(&proxy_server_addr, 0, sizeof(proxy_server_addr));
	proxy_server_addr.sin_family = AF_INET;
	proxy_server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	proxy_server_addr.sin_port = htons(8080); // 사용할 포트번호

	//nSockOpt = 1;
	//setsockopt(m_listen_sock, SOL_SOCKET, SO_REUSEADDR, (const char*) &nSockOpt, sizeof(nSockOpt));

											  // bind 함수를 사용하여 서버 소켓의 주소 설정

	status = ::bind(m_listen_sock, (SOCKADDR *)&proxy_server_addr, sizeof(proxy_server_addr));
	if ((status == SOCKET_ERROR)) {
		printf("bind error : ");
		WSACleanup();
		exit(1);
	}

	// 위에서 지정한 주소로 클라이언트 접속을 기다림
	if (listen(m_listen_sock, 5) != 0) {
		printf("listen error : ");
		exit(1);
	}


	std::thread * thread_arr[MAX_SOCKET_NUMBER];
	int client_addr_size = sizeof(client_addr);
	while (sock_cnt<MAX_SOCKET_NUMBER) {
		mtx.lock();
		int available_sock = checkSocket();
		mtx.unlock();
		if (available_sock != -1)
		{
			m_client_sock[available_sock] = accept(m_listen_sock, (struct sockaddr *) &client_addr, &client_addr_size);
			sock_cnt++;
			if (m_client_sock[available_sock] == INVALID_SOCKET) {
				wprintf(L"accept failed with error: %ld\n", WSAGetLastError());
				closesocket(m_client_sock[available_sock]);
				WSACleanup();
				return 1;
			}
			else
			{
				thread_arr[available_sock] = new std::thread(Sequence, m_client_sock[available_sock], available_sock);
				thread_arr[available_sock]->detach();
				//cout << "# " << available_sock << " Accepted!" << endl;
			}
		}
	}
	WSACleanup();
	return 0;
}