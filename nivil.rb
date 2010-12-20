#! /usr/bin/env ruby


require 'optparse'
require 'uri'
require 'net/https'
require 'rexml/document'

include REXML


options = {}

optparse = OptionParser.new do |opts|
    opts.banner = "Nessus Wrapper for Seccubus v2\nUsage: ./nivil.rb [options] "
    
    
    opts.on('-u', '--user USER', 'Username to login to Nessus') do |username|
      options[:username] = username
    end
    opts.on('-p', '--password PASSWD', 'Password to login to Nessus') do |passwd|
      options[:passwd] = passwd
    end
    opts.on('-s', '--server SERVER', 'Server name (localhost is default)') do |server|
      options[:server] = server
    end
    opts.on('-l', '--policy POLICY', 'Policy to scan with' ) do |policy|
      options[:policy] = policy
    end
    opts.on('-t', '--target TARGET', 'Target to scan') do |target|
      options[:target] = target
    end
    opts.on('-n', '--name NAME', 'Scan name') do |name|
      options[:name] = name
    end
    opts.on('-h', '--help', 'Display help') do
      puts opts
      exit
    end
    opts.on('-v', '--verbose', 'Show Scan Progress to STD OUT') do
        options[:verbose] = true
    end
    opts.on('-f', '--file INFILE', 'File of hosts to scan') do |file|
        options[:file] = file
    end
    opts.on('-o', '--output OUTFILE', 'Name of IVIL output file') do |out|
        options[:out] = out
    end
    opts.on('--show-policies', 'Shows Server Policies') do
        options[:showpol] = true
    end
    opts.on('--show-reports', 'Shows Server Reports') do
        options[:showrpt] = true
    end
    opts.on('-g', '--get-report RPTID', 'Download Report and Export to IVIL/Nessus V2') do |rpt|
        options[:rptid] = rpt
    end
    case ARGV.length
    when 0
      puts opts
      exit
    end
    @fopts = opts
end
optparse.parse!


if !(options[:username] and options[:passwd] and options[:server])
    puts
    puts("**[FAIL]** Missing Arguments")
    puts
    puts @fopts
    exit
end
# Our Connection Class

class NessusConnection
    def initialize(user, pass, server)
        @username = user
        @passwd = pass
        @server = server
        @nurl = "https://#{@server}:8834/"
        @token = nil
    end
    
    def connect(uri, post_data)
        url = URI.parse(@nurl + uri)
        request = Net::HTTP::Post.new( url.path )
        request.set_form_data(post_data)
        if not defined? @https
            @https = Net::HTTP.new( url.host, url.port )
            @https.use_ssl = true
            @https.verify_mode = OpenSSL::SSL::VERIFY_NONE
        end
        begin
            res = @https.request(request)
        rescue
            puts("error connecting to server: #{@nurl} with URI: #{uri}")
            exit
        end
        return res.body
    end
end

class NessusXMLStreamParser
    
    attr_accessor :on_found_host

    def initialize(&block)
        reset_state
        on_found_host = block if block
    end

    def reset_state
        @host = {'hname' => nil, 'addr' => nil, 'mac' => nil, 'os' => nil, 'ports' => [
            'port' => {'port' => nil, 'svc_name'  => nil, 'proto' => nil, 'severity' => nil,
            'nasl' => nil, 'description' => nil, 'cve' => [], 'bid' => [], 'xref' => [], 'msf' => nil } ] }
        @state = :generic_state
    end

    def tag_start(name, attributes)
        case name
        when "tag"
            if attributes['name'] == "mac-address"
                @state = :is_mac
            end
            if attributes['name'] == "host-fqdn"
                @state = :is_fqdn
            end
            if attributes['name'] == "ip-addr"
                @state = :is_ip
            end
            if attributes['name'] == "host-ip"
                @state = :is_ip
            end
            if attributes['name'] == "operating-system"
                @state = :is_os
            end
        when "ReportHost"
            @host['hname'] = attributes['name']
        when "ReportItem"
            @cve = Array.new
            @bid = Array.new
            @xref = Array.new
            @x = Hash.new
            @x['nasl'] = attributes['pluginID']
            @x['port'] = attributes['port']
            @x['proto'] = attributes['protocol']
            @x['svc_name'] = attributes['svc_name']
            @x['severity'] = attributes['severity']
        when "description"
            @state = :is_desc
        when "cve"
            @state = :is_cve
        when "bid"
            @state = :is_bid
        when "xref"
            @state = :is_xref
        when "solution"
            @state = :is_solution
        when "metasploit_name"
            @state = :msf
        end
    end
    
    def text(str)
        case @state
        when :is_fqdn
            @host['hname'] = str
        when :is_ip
            @host['addr'] = str
        when :is_os
            @host['os'] = str
        when :is_mac
            @host['mac'] = str
        when :is_desc
            @x['description'] = str
        when :is_cve
            @cve.push str
        when :is_bid
            @bid.push str
        when :is_xref
            @xref.push str
        when :msf
            @x['msf'] = str
        end
    end

    def tag_end(name)
        case name
        when "ReportHost"
            on_found_host.call(@host) if on_found_host
            reset_state
        when "ReportItem"
            @x['cve'] = @cve
            @x['bid'] = @bid
            @x['xref'] = @xref
            @host['ports'].push @x
        end
        @state = :generic_state
    end

    # We don't need these methods, but they're necessary to keep REXML happy
    #
    def xmldecl(version, encoding, standalone); end
    def cdata; end
    def comment(str); end
    def instruction(name, instruction); end
    def attlist; end
end # end of parser class

#<IVIL version=0.2>
#    <addressee>
#        <program>Seccubus|�
#        <programSpecificData>
#            <ScanID>
#            <ScanID>
#        </programSpecificData>
#    </addressee>
#    <sender>
#        <scanner_type>Nessus|Nikto|MSF|OpenVAS|Qualis|...
#        <version>
#        <timestamp>YYYYMMDDHHMMSS</
#    <sender/>
#    <hosts>
#        <host>
#            <ip>
#	    <findings>
#	        <finding>
#                    <port>
#                    <id>
#                    <severity>
#                    <finding_txt>
#                    <references>
#                        <cve>
#                        <bid>
#                        <osvdb>
#                        <url>
#                        <msf>
#                    </references>
#                </finding>
#            </findings>
#        </host>
#    </hosts>
#</ivil>

def parse_ivil(content)
    parser = NessusXMLStreamParser.new
    ivil = Document.new
    ivil << XMLDecl.new
    ivil.add_element( "ivil", {"version" => "0.2"})
    addressee = ivil.root.add_element("addressee")
    program = addressee.add_element("program")
    program.text = "Seccubus"
    programspecific = addressee.add_element("programSpecificData")
    scanid = programspecific.add_element("ScanID")
    scanid.text = "1"
    sender = ivil.root.add_element("sender")
    scannertype = sender.add_element("scanner_type")
    scannertype.text = "Nessus"
    scanner_version = sender.add_element("version")
    scanner_version.text = "4.2"
    timestamp = sender.add_element("timestamp")
    time = Time.new
    timestamp.text = time.strftime("%Y%m%d%H%M%S")
    hosts = ivil.root.add_element("hosts")
    
    #ivil << "<hosts> "
    parser.on_found_host = Proc.new { |host|
        hostx = hosts.add_element("host")
        addr = host['addr'] || host['hname']
        addr.gsub!(/[\n\r]/," or ") if addr
        ipx = hostx.add_element("ip")
        ipx.text = addr
        os = host['os']
        os.gsub!(/[\n\r]/," or ") if os
        
        hname = host['hname']
        hname.gsub!(/[\n\r]/," or ") if hname
        
        mac = host['mac']
        mac.gsub!(/[\n\r]/," or ") if mac
        findings = hostx.add_element("findings")
        #ivil << "           <findings>"
        host['ports'].each do |item|
            finding = findings.add_element("finding")
            #ivil << "                   <finding>"
            
            exp = []
            msf = nil
            nasl = item['nasl'].to_s
            port = item['port'].to_s
            portx = finding.add_element("port")
            portx.text = port
            #ivil << "                       <port>#{port}</port>"
            proto = item['proto'] || "tcp"
            name = item['svc_name']
            id = finding.add_element("id")
            id.text = name
            #ivil << "                       <id>#{name}</id>"
            severity = item['severity']
            sevx = finding.add_element("severity")
            sevx.text = severity
            #ivil << "                       <severity>#{severity}</severity>"
            description = item['description']
            finding_txt = finding.add_element("finding_txt")
            finding_txt.text = description
            #ivil << "                       <finding_txt>#{description}</finding_txt>"
            #ivil << "                       <references>"
            refs = finding.add_element("references")
            
            cve = item['cve']
            
            if cve
                cve.each do |stuff|
                    cvex = refs.add_element("cve")
                    cvex.text = stuff
                    #ivil << "                       <cve>#{stuff}</cve>"
                end
            end
            
            
            bid = item['bid']
            if bid
                bid.each do |stuff|
                    bidx = refs.add_element("bid")
                    bidx.text = stuff
                    #ivil << "                       <bid>#{stuff}</bid>"
                end
            end
            
            xref = item['xref']
            if xref
                xref.each do |stuff|
                    xrefx = refs.add_element("xref")
                    xrefx.text = stuff
                    #ivil << "                       <xref>#{stuff}</xref>"
                end
            end
            
            msf = item['msf']
            if msf
                msfx = refs.add_element("msf")
                msfx.text = msf
                    #ivil << "                       <msf>#{msf}</msf>"
                
            end
            
            #ivil << "                       </references>"
            #ivil << "                   </finding>"
            
           
            #print("#{addr} | #{os} | #{port} | #{nss} | Sev #{severity} \n")
            
            
        end
        #ivil << "           </findings>"
        #ivil << "   </host>"
    }
    REXML::Document.parse_stream(content, parser)
    #ivil << "</hosts> "
    #ivil << "</IVIL>"
    out = ""
    ivil.write(out, 2)
    
    return out
    
end

def show_policy(options)
    uri = "scan/list"
    post_data = { "token" => @token }
    stuff = @n.connect(uri, post_data)
    docxml = REXML::Document.new(stuff)
    policies=Array.new
    docxml.elements.each('/reply/contents/policies/policies/policy') { |policy|
        entry=Hash.new
        entry['id']=policy.elements['policyID'].text
        entry['name']=policy.elements['policyName'].text
        entry['comment']=policy.elements['policyComments'].text
        policies.push(entry)
    }
    puts("ID\tName")
    policies.each do |policy|
        puts("#{policy['id']}\t#{policy['name']}")
    end 
end

def login(options)
    uri = "login"
    post_data =  { "login" => options[:username], "password" => options[:passwd] }
    #p post_data
    stuff = @n.connect(uri, post_data)
    docxml = REXML::Document.new(stuff)
    if docxml == ''
            @token=''
    else
            @token = docxml.root.elements['contents'].elements['token'].text
            @name = docxml.root.elements['contents'].elements['user'].elements['name'].text
            @admin = docxml.root.elements['contents'].elements['user'].elements['admin'].text
    end
end

def show_reports(options)
    uri = "report/list"
    post_data = { "token" => @token }
    stuff = @n.connect(uri, post_data)
    docxml = REXML::Document.new(stuff)
    reports=Array.new
    docxml.elements.each('/reply/contents/reports/report') {|report|
        entry=Hash.new
        entry['id']=report.elements['name'].text if report.elements['name']
        entry['name']=report.elements['readableName'].text if report.elements['readableName']
        entry['status']=report.elements['status'].text if report.elements['status']
        entry['timestamp']=report.elements['timestamp'].text if report.elements['timestamp']
        reports.push(entry)
    }
    puts("ID\tName")
    reports.each do |report|
        puts("#{report['id']}\t#{report['name']}")
    end 
end

def get_report(options)
    file = nil
    uri = "file/report/download"
    post_data = { "token" => @token, "report" => options[:rptid]  }
    stuff = @n.connect(uri, post_data)
    if options[:out]
        File.open("#{options[:out]}.nessus", 'w') {|f| f.write(stuff) }
        puts("#{options[:out]}.nessus written.")
        ivil = parse_ivil(stuff)
        File.open("#{options[:out]}.ivil", 'w') {|f| f.write(ivil) }
        puts("#{options[:out]}.ivil written.")
        exit
        
    end
    
end


@n = NessusConnection.new(options[:username], options[:passwd], options[:server])
#ok lets check we have everything.

if options[:showpol]
    login(options)
    show_policy(options)
    exit
end

if options[:showrpt]
    login(options)
    show_reports(options)
    exit
end

if options[:rptid]
    login(options)
    get_report(options)
    exit
end

#login
login(options)

##verify policy
uri = "scan/list"
pid = options[:policy]
post_data = { "token" => @token }
stuff = @n.connect(uri, post_data)
docxml = REXML::Document.new(stuff)
policies=Array.new
docxml.elements.each('/reply/contents/policies/policies/policy') { |policy|
    entry=Hash.new
    entry['id']=policy.elements['policyID'].text
    entry['name']=policy.elements['policyName'].text
    entry['comment']=policy.elements['policyComments'].text
    policies.push(entry)
}
match = nil
policies.each {|p|
    if p['id'].to_i == pid.to_i
        #puts("#{pid} - #{p['name']} is valid")
        match = pid
        next
    end
}
if match.nil?
    puts("No Matching Policy ID: #{pid}")
    exit
end

#start scan
uri = "scan/new"
post_data = { "token" => @token, "policy_id" => options[:policy], "scan_name" => options[:name], "target" => options[:target] }
stuff = @n.connect(uri, post_data)
docxml = REXML::Document.new(stuff)
uuid=docxml.root.elements['contents'].elements['scan'].elements['uuid'].text

#loop checking scan, print %done if -v
done = false
puts("Running Scan")
print("[*]")
count = 0
until count == 5
    
    uri = "scan/list"
    post_data = { "token" => @token }
    stuff = @n.connect(uri, post_data)
    docxml = REXML::Document.new(stuff)
    docxml.elements.each('/reply/contents/scans/scanList/scan') {|scan|
        if scan.elements['uuid'].text == uuid
            if scan.elements['status'].text == "running"
                now = scan.elements['completion_current'].text
                total = scan.elements['completion_total'].text
                percent = (now.to_f / total.to_f) * 100
                break if now.to_f == total.to_f
                case count
                    when 0
                        print("\r[|] #{percent.round(2)}% #{now}/#{total}")
                        count += 1
                    when 1
                        print("\r[/] #{percent.round(2)}% #{now}/#{total}")
                        count += 1
                    when 2
                        print("\r[-] #{percent.round(2)}% #{now}/#{total}")
                        count += 1
                    when 3
                        print("\r[\\] #{percent.round(2)}% #{now}/#{total}")
                        count =0
                end
                #print(" Scan is #{now} / #{total}.")
                #sleep 1
                
            else
                break
            end
        else
            break
        end
    }
end
print("\r[*] Scan complete.")

# scan done, get report

#parse report into ivil

#output



