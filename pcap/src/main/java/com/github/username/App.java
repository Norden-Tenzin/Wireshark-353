
package com.github.username;
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

public class App {
	public static void main(String[] args) throws PcapNativeException, NotOpenException {
		System.out.println("Let's start analysis ");
		final PcapHandle handle;
		handle = Pcaps.openOffline("small.pcap");
		PacketListener listener = new PacketListener() {
			public void gotPacket(Packet packet) {
				System.out.println(handle.getTimestamp());
				System.out.println(handle);
				System.out.println("packet info");
				System.out.println(packet);
				IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
				Inet4Address srcAddr = ipV4Packet.getHeader().getSrcAddr();
				System.out.println(srcAddr);
			}
		};
		try {
			int maxPackets = 5;
			handle.loop(maxPackets, listener);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		//Cleanup when complete
		handle.close();
	}
}
