// App.java
package com.github.username;

import java.io.File;
import java.io.*; // Import the FileWriter class

import java.io.IOException;
import java.net.Inet4Address;
import com.sun.jna.Platform;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapStat;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.NifSelector;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;

public class App {
    static int check_number = 0;
    static int UDP_number = 0;
    static int TCP_number = 0;
    static float total_byte = 0;

    static double first_pack_time = 0;
    static double last_pack_time = 0;
    static boolean first_packet_time = false;
    static boolean last_packet_time = false;

    static String toWrite = "";

    public static void main(String[] args) throws PcapNativeException, NotOpenException {
        System.out.println("Let's start analysis ");
        // // New code below here

        final PcapHandle handle;

        handle = Pcaps.openOffline("small.pcap");

        System.out.println("handle");
        System.out.println(handle);

        PacketListener listener = new PacketListener() {
            public void gotPacket(Packet packet) {

                toWrite += packet + "\n";
                // System.out.println(packet);

                String lines[] = packet.getPayload().toString().split("\\r?\\n");

                if (first_packet_time == false) {
                    first_pack_time = (double) handle.getTimestamp().getTime();
                    first_packet_time = true;
                }
                last_pack_time = (double) handle.getTimestamp().getTime();

                check_number = 1 + check_number;
                total_byte = total_byte + (float) packet.length();

                if (packet.get(TcpPacket.class) != null) {
                    UDP_number = UDP_number + 1;
                }

                if (packet.get(UdpPacket.class) != null) {
                    TCP_number = TCP_number + 1;

                    try {
                        // System.out.println("Source: " + lines[11].substring(19));
                        // System.out.println("Dest " + lines[12].substring(24));
                        // System.out.println(lines[33].split(" ")[4]);
                        // System.out.println(lines[34].split(" ")[4]);
                    } catch (ArrayIndexOutOfBoundsException e) {
                        // e.printStackTrace();
                    }
                }

            }
        };

        try {
            int maxPackets = -1;
            handle.loop(maxPackets, listener);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        try {
            File myfile = new File("filename.txt");
            FileWriter myWriter = new FileWriter("filename.txt");
            myWriter.write(toWrite);
            myWriter.close();
        } catch (Exception e) {

        }
        double total_time = last_pack_time - first_pack_time;
        total_time = total_time / 1000.0;

        System.out.println("Total number of packets, " + check_number);
        System.out.println("Total number of UDP packets, " + UDP_number);
        System.out.println("Total number of TCP packets, " + TCP_number);
        System.out.println("Total bandwidth of the packet trace in Mbps, " + total_byte / total_time / 125000.0);

        // Cleanup when complete
        handle.close();
    }
}
