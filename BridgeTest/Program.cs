using ControlPanel.Services;
using System;
using System.Threading;

var bridge = new HttpToSocks5Bridge("68.209.59.238", 8000, "ffg4rp", "ADNde2");
var port = bridge.Start();
Console.WriteLine($"HTTP-to-SOCKS5 bridge listening on 127.0.0.1:{port}");
Console.WriteLine("Press ENTER to stop...");
Thread.Sleep(Timeout.Infinite);
bridge.Stop();
