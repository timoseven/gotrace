package main

import (
    "fmt"
    "flag"
    "golang.org/x/net/icmp"
    "golang.org/x/net/ipv4"
    "github.com/oschwald/geoip2-golang"
    "log"
    "net"
    "os"
    "time"
//    "strconv"
)


func findaddr(ipaddr net.Addr) (country string, asn uint) {
    db, err := geoip2.Open("./resource/GeoIP2-City.mmdb")
    asndb, err := geoip2.Open("./resource/GeoLite2-ASN.mmdb")
    if err != nil {
        log.Panic(err)
    }
    defer db.Close()
    defer asndb.Close()
    // If you are using strings that may be invalid, check that ip is not nil
    ip := net.ParseIP(ipaddr.String())

    record, err := db.City(ip)
    if err != nil {
        log.Panic(err)
    }

    asrecord, err := asndb.ASN(ip)
    if err != nil {
        log.Panic(err)
    }

    asn = asrecord.AutonomousSystemNumber
    country = record.Country.IsoCode
//    }
    return
//    fmt.Printf("Russian country name: %v\n", record.Country.Names["en"])
//    fmt.Printf("ISO country code: %v\n", record.Country.IsoCode)
//    fmt.Printf("Time zone: %v\n", record.Location.TimeZone)
//    fmt.Printf("Coordinates: %v, %v\n", record.Location.Latitude, record.Location.Longitude)
// Output:
// Portuguese (BR) city name: Londres
// English subdivision name: England
// Russian country name: Великобритания
// ISO country code: GB
// Time zone: Europe/London
// Coordinates: 51.5142, -0.0931
}

func main() {

    // Tracing an IP packet route to www.baidu.com.


//    const host = "www.baidu.com"
    var host        string
    flag.StringVar(&host, "H", "www.baidu.com", "默认www.baidu.com")
    flag.Parse()

    ips, err := net.LookupIP(host)
    if err != nil {
        log.Fatal(err)
    }
    var dst net.IPAddr
    for _, ip := range ips {
        if ip.To4() != nil {
            dst.IP = ip
            fmt.Printf("using %v for tracing an IP packet route to %s\n", dst.IP, host)
            break
        }
    }
    if dst.IP == nil {
        log.Fatal("no A record found")
    }

    c, err := net.ListenPacket("ip4:1", "0.0.0.0") // ICMP for IPv4
    if err != nil {
        log.Fatal(err)
    }
    defer c.Close()
    p := ipv4.NewPacketConn(c)

    if err := p.SetControlMessage(ipv4.FlagTTL|ipv4.FlagSrc|ipv4.FlagDst|ipv4.FlagInterface, true); err != nil {
        log.Fatal(err)
    }
    wm := icmp.Message{
        Type: ipv4.ICMPTypeEcho, Code: 0,
        Body: &icmp.Echo{
            ID:   os.Getpid() & 0xffff,
            Data: []byte("HELLO-R-U-THERE"),
        },
    }

    rb := make([]byte, 1500)
    for i := 1; i <= 64; i++ { // up to 64 hops
        wm.Body.(*icmp.Echo).Seq = i
        wb, err := wm.Marshal(nil)
        if err != nil {
            log.Fatal(err)
        }
        if err := p.SetTTL(i); err != nil {
            log.Fatal(err)
        }

        // In the real world usually there are several
        // multiple traffic-engineered paths for each hop.
        // You may need to probe a few times to each hop.
        begin := time.Now()
        if _, err := p.WriteTo(wb, nil, &dst); err != nil {
            log.Fatal(err)
        }
        if err := p.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
            log.Fatal(err)
        }
        n, _, peer, err := p.ReadFrom(rb)
        if err != nil {
            if err, ok := err.(net.Error); ok && err.Timeout() {
                fmt.Printf("%v\t*\tNULL\n", i)
                continue
            }
            log.Fatal(err)
        }
        rm, err := icmp.ParseMessage(1, rb[:n])
        if err != nil {
            log.Fatal(err)
        }
        rtt := time.Since(begin)

        // In the real world you need to determine whether the
        // received message is yours using ControlMessage.Src,
        // ControlMessage.Dst, icmp.Echo.ID and icmp.Echo.Seq.
        switch rm.Type {
        case ipv4.ICMPTypeTimeExceeded:
            names, _ := net.LookupAddr(peer.String())
            fcountry, fasn := findaddr(peer)
	    fmt.Printf("%d\t%v %+v %v\tCountry_code:%v\tAS:%d\n", i, peer, names, rtt, fcountry, fasn)
        case ipv4.ICMPTypeEchoReply:
            names, _ := net.LookupAddr(peer.String())
            fcountry, fasn := findaddr(peer)
	    fmt.Printf("%d\t%v %+v %v\tCountry_code:%v\tAS:%d\n", i, peer, names, rtt, fcountry, fasn)
            return
        default:
            log.Printf("unknown ICMP message: %+v\n", rm)
        }
    }
}
