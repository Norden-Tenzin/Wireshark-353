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
  static double total_byte = 0;

  static double first_pack_time = 0;
  static double last_pack_time = 0;
  static boolean first_packet_time = false;
  static boolean last_packet_time = false;

  static String toWrite = "";

  static ArrayList<Flow> flowHolder = new ArrayList<Flow>();

  public static void main(String[] args)
    throws PcapNativeException, NotOpenException {
    System.out.println("Let's start analysis ");

    final PcapHandle handle;

    handle = Pcaps.openOffline("small.pcap");

    System.out.println("handle");
    System.out.println(handle);

    PacketListener listener = new PacketListener() {
      public void gotPacket(Packet packet) {
        String lines[] = packet.getPayload().toString().split("\\r?\\n");
        if (first_packet_time == false) {
          first_pack_time = (double) handle.getTimestamp().getTime();
          first_packet_time = true;
        }
        last_pack_time = (double) handle.getTimestamp().getTime();
        check_number = 1 + check_number;
        total_byte = total_byte + (double) packet.length();

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
            Flow f1 = new Flow(
              sip,
              Integer.parseInt(sport),
              dip,
              Integer.parseInt(dport)
            );
            for (Flow f : flowHolder) {
              if (f.id().equals(f1.id())) {
                flowExists = true;
                if (syn == true) {
                  f.foundSYN();
                }
                if (fin == true) {
                  f.foundFIN();
                }
                f.setTime((double) handle.getTimestamp().getTime());
                f.incCompletedBytes((double) packet.length());
                f.incTotalBytes((double) packet.length());
                f.incPackets();
              }
            }
            if (flowExists == false) {
              // new values
              if (syn == true) {
                f1.foundSYN();
              }
              if (fin == true) {
                f1.foundFIN();
              }
              f1.setTime((double) handle.getTimestamp().getTime());
              f1.incCompletedBytes((double) packet.length());
              f1.incTotalBytes((double) packet.length());
              f1.incPackets();
              flowHolder.add(f1);
            }
            flowExists = false;
          } catch (ArrayIndexOutOfBoundsException e) {
            e.printStackTrace();
          }
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

    // double total_time = last_pack_time - first_pack_time;
    // total_time = total_time / 1000.0;

    for (Flow f : flowHolder) {
      f.incNoFin();
      System.out.println(f.toString());
    }

    // System.out.println("TCP Summary Table");
    // System.out.println("Total number of packets, " + check_number);
    // System.out.println("Total number of UDP packets, " + UDP_number);
    // System.out.println("Total number of TCP packets, " + TCP_number);
    // System.out.println(
    //   "Total bandwidth of the packet trace in Mbps, " +
    //   total_byte /
    //   total_time /
    //   125000.0
    // );
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
  int packetUk;

  double totalBytes;
  double inCompletedBytes;
  double completedBytes;

  double avgBandwidth;
  boolean foundSYN = false;
  boolean foundFIN = false;
  boolean haveFirstTime = false;
  boolean firstFin = true;
  double firstTime;
  double lastTime;

  Flow(String sip, int sport, String dip, int dport) {
    this.sIp = sip;
    this.dIp = dip;
    this.sPort = sport;
    this.dPort = dport;
    this.totalBytes = 0;
    this.inCompletedBytes = 0;
    this.completedBytes = 0;
    this.packetComplete = 0;
    this.packetInComplete = 0;
    this.packetUk = 0;
  }

  void foundSYN() {
    this.foundSYN = true;
  }

  void foundFIN() {
    this.foundFIN = true;
  }

  void incPackets() {
    if (this.foundSYN == false && this.foundFIN == false) { // both not found
      this.packetInComplete += 1;
    }
    if (this.foundSYN == true && this.foundFIN == false) { // found syn
      this.packetUk += 1;
    } else if (this.foundSYN == false && this.foundFIN == true) {
      this.packetInComplete += 1;
      this.foundFIN = false;
    }
    if (this.foundSYN == true && this.foundFIN == true) {
      this.packetComplete = this.packetUk + 1;
      this.packetUk = 0;
      this.foundFIN = false;
      this.foundSYN = false;
    }
  }

  void incCompletedBytes(double b) {
    if (this.foundSYN == true && this.foundFIN == true) {
      this.completedBytes = this.inCompletedBytes + b;
    }
    if (this.foundSYN == true && this.foundFIN == false) {
      this.inCompletedBytes += b;
    }
  }

  void incNoFin() {
    if (this.packetUk > 0) {
      this.packetInComplete = this.packetUk;
    }
  }

  void incTotalBytes(double b) {
    this.totalBytes += b;
  }

  void setTime(double t) {
    if (haveFirstTime == false && this.foundSYN == true) {
      this.firstTime = t;
      this.haveFirstTime = true;
    }
    if (
      haveFirstTime == true &&
      this.foundSYN == true &&
      this.foundFIN == true &&
      this.firstFin == true
    ) {
      this.lastTime = t;
      this.firstFin = false;
    }
  }

  public String id() {
    return (sIp + ", " + sPort + ", " + dIp + ", " + dPort);
  }

  public String toString() {
    double totalTime = this.lastTime - this.firstTime;
    totalTime = totalTime / 1000000;
    this.avgBandwidth = (double) this.completedBytes / totalTime / 125000.0;
    if (this.packetComplete == 0) {
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
        packetInComplete
      );
    } else {
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
        totalBytes +
        ", " +
        avgBandwidth
      );
    }
  }
}
