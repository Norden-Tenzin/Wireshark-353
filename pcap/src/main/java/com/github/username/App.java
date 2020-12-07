// App.java
package com.github.username;

import com.sun.jna.Platform;
import java.io.*; // Import the FileWriter class
import java.io.File;
import java.io.IOException;
import java.net.Inet4Address;
import java.util.*;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.PcapStat;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.util.NifSelector;

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

  static ArrayList<Flow> flowHolder = new ArrayList<Flow>();

  public static void main(String[] args)
    throws PcapNativeException, NotOpenException {
    System.out.println("Let's start analysis ");
    // // New code below here

    final PcapHandle handle;

    handle = Pcaps.openOffline("small.pcap");

    System.out.println("handle");
    System.out.println(handle);

    PacketListener listener = new PacketListener() {
      public void gotPacket(Packet packet) {
        // toWrite += packet + "\n";
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
          try {
            boolean flowExists = false;
            String sip = packet
              .get(IpV4Packet.class)
              .getHeader()
              .toString()
              .split("\\r?\\n")[11].substring(19);
            String dip = packet
              .get(IpV4Packet.class)
              .getHeader()
              .toString()
              .split("\\r?\\n")[12].substring(24);
            String sport = packet
              .get(TcpPacket.class)
              .toString()
              .split("\\r?\\n")[1].split(" ")[4];
            String dport = packet
              .get(TcpPacket.class)
              .toString()
              .split("\\r?\\n")[2].split(" ")[4];

            boolean syn = Boolean.parseBoolean(
              packet
                .get(TcpPacket.class)
                .toString()
                .split("\\r?\\n")[11].split(" ")[3]
            );
            boolean fin = Boolean.parseBoolean(
              packet
                .get(TcpPacket.class)
                .toString()
                .split("\\r?\\n")[12].split(" ")[3]
            );

            System.out.println(packet.get(TcpPacket.class));
            System.out.println(
              packet
                .get(TcpPacket.class)
                .toString()
                .split("\\r?\\n")[11].split(" ")[3]
            );

            Flow f1 = new Flow(
              sip,
              Integer.parseInt(sport),
              dip,
              Integer.parseInt(dport)
            );
            for (Flow f : flowHolder) {
              if (f.id().equals(f1.id())) {
                flowExists = true;
                // change the values.
                f.setTime((double) handle.getTimestamp().getTime());
                if (syn == true) {
                  f.foundSYN();
                }
                if (fin = true) {
                  f.foundFIN();
                }
                f.incPackets();
                f.incTotalBytes((float) packet.length());
              }
            }
            if (flowExists == false) {
              // new values
              f1.setTime((double) handle.getTimestamp().getTime());
              if (syn == true) {
                f1.foundSYN();
              }
              if (fin = true) {
                f1.foundFIN();
              }
              f1.incPackets();
              f1.incTotalBytes((float) packet.length());
              flowHolder.add(f1);
            }

            flowExists = false;
            // System.out.println("Dest " + lines[12].substring(24));
            // System.out.println(lines[33].split(" ")[4]);
            // System.out.println(lines[34].split(" ")[4]);
          } catch (ArrayIndexOutOfBoundsException e) {
            // e.printStackTrace();
          }

          // why does the UDP number go up ?
          UDP_number = UDP_number + 1;
        }

        if (packet.get(UdpPacket.class) != null) {
          TCP_number = TCP_number + 1;
        }
      }
    };

    try {
      int maxPackets = -1;
      handle.loop(maxPackets, listener);
    } catch (InterruptedException e) {
      e.printStackTrace();
    }

    // writes packets to a testfilereturn (
    // try {
    //     File myfile = new File("filename.txt");
    //     FileWriter myWriter = new FileWriter("filename.txt");
    //     myWriter.write(toWrite);
    //     myWriter.close();
    // } catch (Exception e) {
    // }

    double total_time = last_pack_time - first_pack_time;
    total_time = total_time / 1000.0;

    for (Flow f : flowHolder) {
      System.out.println(f.toString());
    }

    System.out.println("TCP Summary Table");
    System.out.println("Total number of packets, " + check_number);
    System.out.println("Total number of UDP packets, " + UDP_number);
    System.out.println("Total number of TCP packets, " + TCP_number);
    System.out.println(
      "Total bandwidth of the packet trace in Mbps, " +
      total_byte /
      total_time /
      125000.0
    );

    // Cleanup when complete
    handle.close();
  }
}

class Flow {

  String sIp;
  int sPort;
  String dIp;
  int dPort;
  int packetComplete;
  int packetInComplete;
  float totalByte;
  double avgBandwidth;
  boolean foundSYN = false;
  boolean foundFIN = false;
  boolean haveFirstTime = false;

  double firstTime;
  double lastTime;

  Flow(String sip, int sport, String dip, int dport) {
    this.sIp = sip;
    this.dIp = dip;
    this.sPort = sport;
    this.dPort = dport;
    this.totalByte = 0;
    this.packetComplete = 0;
    this.packetInComplete = 0;
  }

  void foundSYN() {
    this.foundSYN = true;
  }

  void foundFIN() {
    this.foundFIN = true;
  }

  void incPackets() {
    if (foundSYN == false && foundFIN == false) {
      this.packetInComplete += 1;
    }
    if (foundSYN == true && foundFIN == false) {
      this.packetInComplete += 1;
    } else if (foundSYN == false && foundFIN == true) {
      this.packetInComplete += 1;
    }
    if (foundSYN == true && foundFIN == true) {
      this.packetComplete = this.packetInComplete + 1;
    }
  }

  void incTotalBytes(float b) {
    this.totalByte += b;
  }

  void setTime(double t) {
    if (haveFirstTime == false) {
      this.firstTime = t;
      this.haveFirstTime = true;
    }
    this.lastTime = t;
  }

  public String id() {
    return (sIp + ", " + sPort + ", " + dIp + ", " + dPort);
  }

  public String toString() {
    return (
      sIp +
      ", " +
      sPort +
      ", " +
      dIp +
      ", " +
      dPort +
      ", " +
      packetComplete +
      ", " +
      packetInComplete +
      ", " +
      totalByte +
      ", " +
      avgBandwidth
    );
  }
}
