#include <iostream>
#include <fstream>
#include <ostream>
#include <string>
#include <iomanip>
#include <sstream>
#include <vector>
using namespace std;

long GetFileSize(string filename)
{
	struct stat stat_buf;
	int rc = stat(filename.c_str(), &stat_buf);
	return rc == 0 ? stat_buf.st_size : -1;
}

// Возвращает строку из следующих 6 байт, приведенных к виду MAC-адреса.
string MAC_address(char* buff)
{
	stringstream res;
	unsigned char x;
	for (int i = 0; i < 5; i++)
	{
		x = buff[i];
		res << hex << uppercase << setw(2) << setfill('0') << (int)x << ':';
	}
	x = buff[5];
	res << hex << uppercase << setw(2) << setfill('0') << (int)x;

	return res.str();
}

// Возвращает строку из следующих 4 байт, приведенных к виду IP-адреса.
string IP_address(char* buff)
{
	stringstream res;
	res << dec;
	unsigned char x;
	for (int i = 0; i < 3; i++)
	{
		x = buff[i];
		res << int(x) << '.';
	}
	x = buff[3];
	res << int(x);

	return res.str();
}

// Напечатать информацию по фрейму
unsigned printFrameInformation(ostream& out, char* buff, unsigned pos, int frame_num, vector<int>& counter)
{
	unsigned res = 0;
	out << "Number frame: " << frame_num << endl;
	out << "MAC-address destination: " << MAC_address(buff + pos) << endl;
	out << "MAC-address source: " << MAC_address(buff + pos + 6) << endl;

	uint16_t data_size = buff[pos + 12] << 8 | buff[pos + 13];
	res = data_size;

	if (data_size > 0x05DC)
	{
		counter[0]++;
		out << "Frame type: Ethernet II" << endl;
		res = 0;
		uint8_t Hl, Pl;
		switch (data_size)
		{
		case 0x800:
		{
			counter[4]++;
			// IPv4
			out << "Protocol type: IPv4" << endl;
			out << "Version: " << (int)((buff[pos + 14] & 0xF0) >> 4) << endl;
			out << "Header length: " << (int)(buff[pos + 14] & 0x0F) * 4 << " byte" << endl;
			uint8_t f = buff[pos + 16], s = buff[pos + 17];
			res = f << 8 | s;
			out << "Datagram length: " << res << " byte" << endl;
			if (res < 46)
				res += 46 - res;
			out << "Protocol: " << ((int)buff[pos + 23] == 6 ? "TCP" : "") << ((int)buff[pos + 23] == 17 ? "UDP" : "") << endl;
			out << "IP destination: " << IP_address(buff + pos + 26) << endl;
			out << "IP source: " << IP_address(buff + pos + 30) << endl;
			break;
		}
		case 0x806:
			counter[5]++;
			out << "Protocol type: ARP-request" << endl;
			out << "Hardware type: " << hex << (buff[pos + 14] << 8 | buff[pos + 15]) << dec << endl;
			out << "Protocol type: " << (buff[pos + 16] << 8 | buff[pos + 17]) << endl;
			Hl = buff[pos + 18];
			out << "Hardware length: " << (int)Hl << " byte" << endl;
			Pl = buff[pos + 19];
			out << "Protocol lenght: " << (int)Pl << " byte" << endl;
			out << "Operation: " << (buff[21] == 1 ? "request" : "answer") << endl;
			out << "Sender MAC: " << MAC_address(buff + 22 + pos) << endl;
			out << "Sender IP: " << IP_address(buff + 28 + pos) << endl;
			out << "Target hardware adress: " << MAC_address(buff + 32 + pos) << endl;
			out << "Target protocol adress: " << IP_address(buff + 38 + pos) << endl;
			res = 28 + 18; // Длина пакета ARP-запроса. https://ru.wikipedia.org/wiki/ARP + 19 заполнение
			break;
		case 0x08DD:
			out << "Protocol type: IPv6" << endl;
			break;
		default:
			// http://standards-oui.ieee.org/ethertype/eth.txt
			out << "Protocol type: " << hex << setw(4) << setfill('0') << data_size << dec << endl;
		}
	}
	else
	{
		uint16_t d = buff[pos + 14] << 8 | buff[pos + 15];
		if (d == 0xFFFF)
		{
			counter[1]++;
			out << "Frame type: Raw 802.3 (Ethernet 802.3)" << endl;
		}
		else if (d == 0xAAAA)
		{
			counter[2]++;
			out << "Frame type: Ethernet SNAP" << endl;
		}
		else
		{
			counter[3]++;
			out << "Frame type: Ethernet 802.3/LLC" << endl;
		}
	}

	// 14 = количество байт для заголовка Ethernet-фрейма.
	return res + 14;
}

int main()
{
	// Вводим имя бинарного файла
	ifstream* in;
	string path = "";
	do
	{
		cout << "Enter filename: ";
		cin >> path;
		in = new ifstream(path, ios::binary);
	} while (!in->good());

	long size = GetFileSize(path);
	cout << "File size: " << size << endl;

	// Считываем данные
	char* buff = new char[size];
	in->read(buff, size);

	// Вывод
	int pos = 0;
	int i = 1;
	vector<int> counter(6);
	while (pos < size)
	{
		cout << "Start position of the frame: " << pos << endl;
		cout << "* * * * * * * * *" << endl;
		pos += printFrameInformation(cout, buff, pos, i++, counter);
		cout << "* * * * * * * * *" << endl;
	}

	cout << "Results" << endl;
	cout << "Ethernet II: " << counter[0] << endl
		<< "Raw 802.3 (Ethernet 802.3): " << counter[1] << endl
		<< "Ethernet SNAP: " << counter[2] << endl
		<< "Ethernet 802.3 LLC: " << counter[3] << endl
		<< "Frames count: " << i - 1 << endl
		<< "IPv4: " << counter[4] << endl
		<< "ARP: " << counter[5] << endl
		<< "Done!" << endl;
	return 0;
}