--[[
    Description:
    For SIP Trunks, CUCM CAC will deduct bandwidth from the location that is applied to the SIP trunk when a call is sent over that trunk.
    If the other end of the SIP trunk directs the media to another location CUCM CAC is now possibly deducting the bandwidth from the wrong location.
    Cisco has the ability to work around this with ELCAC. When the SIP trunk is configured in the shadow location, the trunk will accept the location name and bandwidth class in the call-info header of the SIP message:
    Call-Info: <urn:x-cisco-remotecc:callinfo>;x-cisco-loc-id=<GUID>;x-cisco-loc-name=<LOCATION_NAME>;x-cisco;fateshare;id=<FATESHARE-ID>;x-cisco-video-traffic-class=desktop

    But this relies on the remote endpoint adding this information into the SIP message, but what if the remote endpoint doesnt support this?
    Solution
        * Grab the Media Address from the SDP
        * Look this up in a table and finds the associated location NAME and GUID
        * Re-write the call-info header
        * Submit the modified SIP message to Call Manager

    Copyright (c) 2015 Aaron Daniels <aaron@daniels.id.au>
    License: TBA

    This script contains a fair bit of logging, please disable trace when not necessary.
--]]

M = {}
trace.enable()

-- This function turns a decimal number into a padded binary string
-- Oh if only CUCM Lua would support the math library.
local function dec2bin(dec,pad)
    local result = ""
    repeat
        -- Half the decimal number
        local divres = dec / 2

        -- Find any remainder
        local part
        for i in string.gfind(divres, "(%..)") do
            part = i
        end

        -- Determine if we have a 0 or 1, prepend it to the start of our running result
        if part == nil then
            -- if there is no remainder then we have a binary 0
            result = "0" .. result
            dec = divres
            trace.format("-- Dec: "..tostring(dec)..", "..tostring(divres).." has no remainder")
        else
            -- if there is a remainder then we have a binary 1
            result = "1" .. result
            dec = divres - part
            trace.format("-- Dec: "..tostring(dec)..", "..tostring(divres).." has remainder: " .. tostring(part))
        end

        -- repeat until we have turned all the decimal into binary.
    until dec == 0

    -- Pad the binary string to pad characters if it is less.
    len = string.len(result)
    if len < pad then
        local pre = ""
        for i=1,pad-len do
            pre = pre .. "0"
        end
        trace.format("Result: "..len..", Pad: "..pad.." - Padding Required")
        trace.format("Before Padding: "..result..", After: "..pre..result)
        result = pre .. result
    else
        trace.format("Result: "..len..", Pad: "..pad.." - Padding NOT Required")
    end
    return result

end

local function getAddress(msg)
    -- Extract the IPv6 address from the SDP
    local sdp = msg:getSdp()
    if sdp then
        local ipv4_c_line = sdp:getLine("c=", "IP4")
        -- c=IN IP4 192.168.174.10

        ipv4_addr = ipv4_c_line:match("IP4 (%d+.%d+.%d+.%d+)")
        trace.format("-- Extracted ipv4 address: " .. ipv4_addr .. " --")
    end
    return ipv4_addr
end

local function buildCallInfo(msg, LOCATION)
    -- Build the Call-Info Header and return it.
    local HDR_CID = msg:getHeader("Call-ID")
    if HDR_CID then
        trace.format("-- Call-ID Header: " .. HDR_CID .. " --")
        CID = HDR_CID:gsub("-", '')
        if CID then
            CID = CID:match("(%w+)@")
            trace.format("-- Have Call-ID: " .. CID .. " --")
        end
    end

    local CINFO = msg:getHeader("Call-Info")
    if CINFO then
        trace.format("-- Got Call-Info Header, Remove it.")
        msg:removeHeader("Call-Info")
    else
        trace.format("-- No Call-Info Header, need to build one.")
    end

--    Example Call-Info Header: "<urn:x-cisco-remotecc:callinfo>;x-cisco-loc-id=<GUID>;x-cisco-loc-name=<LOCATION_NAME>;x-cisco;fateshare;id=<FATESHARE-ID>;x-cisco-video-traffic-class=desktop"
    local CINFO = "<urn:x-cisco-remotecc:callinfo>;x-cisco-loc-id="..LOCATION["PKID"]..";x-cisco-loc-name="..LOCATION["NAME"]..";x-cisco;fateshare;id="..CID..";x-cisco-video-traffic-class=desktop"
    trace.format("-- Built Call-Info Header: " .. CINFO)

    return CINFO
end

-- From the supplied ADDRESS, return a Location Name and made up PKID.
local function getLocation(ADDRESS)
    trace.format("-- Supplied Address: " .. ADDRESS .. " --")

    -- Create an empty RESPONSE hash, this will be returned.
    local RESPONSE = {}

    -- Locations table, edit this as necessary to tell CUCM which networks belong to which location.
    -- PKID's generated from: http://www.guidgenerator.com
    local LOC_COUNT = 137     -- Must match the amount of locations we have in our table.
    local LOCATIONS = {
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.101.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.102.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.103.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.104.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.105.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.106.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.107.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.108.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.109.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.110.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.111.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.112.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.113.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.114.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.115.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.116.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.117.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.118.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.119.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.120.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.121.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.122.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.123.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.124.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.125.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.126.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.127.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.128.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.129.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.130.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.131.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.132.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.133.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.134.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.135.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.136.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.137.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.138.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.139.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.140.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.141.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.142.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.143.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.144.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.145.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.146.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.147.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.148.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.149.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.150.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.151.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.152.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.153.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.154.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.155.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.156.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.157.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.158.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.159.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.160.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.161.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.162.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.163.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.164.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.165.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.166.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.167.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.168.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.169.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.170.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.171.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.172.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.173.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.74.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.175.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.176.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.177.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.178.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.179.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.180.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.181.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.182.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.183.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.184.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.185.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.186.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.187.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.188.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.189.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.190.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.191.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.192.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.193.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.194.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.195.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.196.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.197.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.198.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.199.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.200.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.101.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.102.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.103.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.104.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.105.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.106.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.107.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.108.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.109.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.110.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.101.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.102.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.103.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.104.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.105.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.106.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.107.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.108.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.109.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.110.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.101.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.102.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.103.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.104.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.105.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.106.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.107.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.108.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.109.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.110.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.101.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.102.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.103.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.104.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.105.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.105.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-3", ["PREFIX"]="192.168.0.0", ["LENGTH"]="16", ["PKID"]="3eed0571-38b7-4f09-9182-d1b8ad6b34cc"},
    }

    -- Converting the decimal to binary is too expensive for CUCM (LuaInstructionThreshold), pull it from a table instead.
    local tblBIN = {
        ["0"] = "00000000", ["1"] = "00000001", ["2"] = "00000010", ["3"] = "00000011", ["4"] = "00000100", ["5"] = "00000101", ["6"] = "00000110", ["7"] = "00000111", ["8"] = "00001000", ["9"] = "00001001",
        ["10"] = "00001010", ["11"] = "00001011", ["12"] = "00001100", ["13"] = "00001101", ["14"] = "00001110", ["15"] = "00001111", ["16"] = "00010000", ["17"] = "00010001", ["18"] = "00010010", ["19"] = "00010011",
        ["20"] = "00010100", ["21"] = "00010101", ["22"] = "00010110", ["23"] = "00010111", ["24"] = "00011000", ["25"] = "00011001", ["26"] = "00011010", ["27"] = "00011011", ["28"] = "00011100", ["29"] = "00011101",
        ["30"] = "00011110", ["31"] = "00011111", ["32"] = "00100000", ["33"] = "00100001", ["34"] = "00100010", ["35"] = "00100011", ["36"] = "00100100", ["37"] = "00100101", ["38"] = "00100110", ["39"] = "00100111",
        ["40"] = "00101000", ["41"] = "00101001", ["42"] = "00101010", ["43"] = "00101011", ["44"] = "00101100", ["45"] = "00101101", ["46"] = "00101110", ["47"] = "00101111", ["48"] = "00110000", ["49"] = "00110001",
        ["50"] = "00110010", ["51"] = "00110011", ["52"] = "00110100", ["53"] = "00110101", ["54"] = "00110110", ["55"] = "00110111", ["56"] = "00111000", ["57"] = "00111001", ["58"] = "00111010", ["59"] = "00111011",
        ["60"] = "00111100", ["61"] = "00111101", ["62"] = "00111110", ["63"] = "00111111", ["64"] = "01000000", ["65"] = "01000001", ["66"] = "01000010", ["67"] = "01000011", ["68"] = "01000100", ["69"] = "01000101",
        ["70"] = "01000110", ["71"] = "01000111", ["72"] = "01001000", ["73"] = "01001001", ["74"] = "01001010", ["75"] = "01001011", ["76"] = "01001100", ["77"] = "01001101", ["78"] = "01001110", ["79"] = "01001111",
        ["80"] = "01010000", ["81"] = "01010001", ["82"] = "01010010", ["83"] = "01010011", ["84"] = "01010100", ["85"] = "01010101", ["86"] = "01010110", ["87"] = "01010111", ["88"] = "01011000", ["89"] = "01011001",
        ["90"] = "01011010", ["91"] = "01011011", ["92"] = "01011100", ["93"] = "01011101", ["94"] = "01011110", ["95"] = "01011111", ["96"] = "01100000", ["97"] = "01100001", ["98"] = "01100010", ["99"] = "01100011",
        ["100"] = "01100100", ["101"] = "01100101", ["102"] = "01100110", ["103"] = "01100111", ["104"] = "01101000", ["105"] = "01101001", ["106"] = "01101010", ["107"] = "01101011", ["108"] = "01101100", ["109"] = "01101101",
        ["110"] = "01101110", ["111"] = "01101111", ["112"] = "01110000", ["113"] = "01110001", ["114"] = "01110010", ["115"] = "01110011", ["116"] = "01110100", ["117"] = "01110101", ["118"] = "01110110", ["119"] = "01110111",
        ["120"] = "01111000", ["121"] = "01111001", ["122"] = "01111010", ["123"] = "01111011", ["124"] = "01111100", ["125"] = "01111101", ["126"] = "01111110", ["127"] = "01111111", ["128"] = "10000000", ["129"] = "10000001",
        ["130"] = "10000010", ["131"] = "10000011", ["132"] = "10000100", ["133"] = "10000101", ["134"] = "10000110", ["135"] = "10000111", ["136"] = "10001000", ["137"] = "10001001", ["138"] = "10001010", ["139"] = "10001011",
        ["140"] = "10001100", ["141"] = "10001101", ["142"] = "10001110", ["143"] = "10001111", ["144"] = "10010000", ["145"] = "10010001", ["146"] = "10010010", ["147"] = "10010011", ["148"] = "10010100", ["149"] = "10010101",
        ["150"] = "10010110", ["151"] = "10010111", ["152"] = "10011000", ["153"] = "10011001", ["154"] = "10011010", ["155"] = "10011011", ["156"] = "10011100", ["157"] = "10011101", ["158"] = "10011110", ["159"] = "10011111",
        ["160"] = "10100000", ["161"] = "10100001", ["162"] = "10100010", ["163"] = "10100011", ["164"] = "10100100", ["165"] = "10100101", ["166"] = "10100110", ["167"] = "10100111", ["168"] = "10101000", ["169"] = "10101001",
        ["170"] = "10101010", ["171"] = "10101011", ["172"] = "10101100", ["173"] = "10101101", ["174"] = "10101110", ["175"] = "10101111", ["176"] = "10110000", ["177"] = "10110001", ["178"] = "10110010", ["179"] = "10110011",
        ["180"] = "10110100", ["181"] = "10110101", ["182"] = "10110110", ["183"] = "10110111", ["184"] = "10111000", ["185"] = "10111001", ["186"] = "10111010", ["187"] = "10111011", ["188"] = "10111100", ["189"] = "10111101",
        ["190"] = "10111110", ["191"] = "10111111", ["192"] = "11000000", ["193"] = "11000001", ["194"] = "11000010", ["195"] = "11000011", ["196"] = "11000100", ["197"] = "11000101", ["198"] = "11000110", ["199"] = "11000111",
        ["200"] = "11001000", ["201"] = "11001001", ["202"] = "11001010", ["203"] = "11001011", ["204"] = "11001100", ["205"] = "11001101", ["206"] = "11001110", ["207"] = "11001111", ["208"] = "11010000", ["209"] = "11010001",
        ["210"] = "11010010", ["211"] = "11010011", ["212"] = "11010100", ["213"] = "11010101", ["214"] = "11010110", ["215"] = "11010111", ["216"] = "11011000", ["217"] = "11011001", ["218"] = "11011010", ["219"] = "11011011",
        ["220"] = "11011100", ["221"] = "11011101", ["222"] = "11011110", ["223"] = "11011111", ["224"] = "11100000", ["225"] = "11100001", ["226"] = "11100010", ["227"] = "11100011", ["228"] = "11100100", ["229"] = "11100101",
        ["230"] = "11100110", ["231"] = "11100111", ["232"] = "11101000", ["233"] = "11101001", ["234"] = "11101010", ["235"] = "11101011", ["236"] = "11101100", ["237"] = "11101101", ["238"] = "11101110", ["239"] = "11101111",
        ["240"] = "11110000", ["241"] = "11110001", ["242"] = "11110010", ["243"] = "11110011", ["244"] = "11110100", ["245"] = "11110101", ["246"] = "11110110", ["247"] = "11110111", ["248"] = "11111000", ["249"] = "11111001",
        ["250"] = "11111010", ["251"] = "11111011", ["252"] = "11111100", ["253"] = "11111101", ["254"] = "11111110", ["255"] = "11111111",
    }

    -- Gets get the bin of our IP.
    local BINSDP = ""
    for i in string.gfind(ADDRESS, "(%w+)") do
        BINSDP = BINSDP .. tblBIN[i]
    end

    -- Loop over our table looking for our location
    for row=1,LOC_COUNT do
        local BINPFX = ""
        for i in string.gfind(LOCATIONS[row]["PREFIX"], "(%w+)") do
            BINPFX = BINPFX .. tblBIN[i]
        end

        -- See if the IP2 and IP2 are on the same network.
        if string.sub(BINSDP, 0, LOCATIONS[row]["LENGTH"]) == string.sub(BINPFX, 0, LOCATIONS[row]["LENGTH"]) then
            trace.format("Yes - "..ADDRESS.." is on the same network as "..LOCATIONS[row]["PREFIX"].." which has a "..LOCATIONS[row]["LENGTH"].." bit length")
            return LOCATIONS[row]
        else
            trace.format("No - "..ADDRESS.." is NOT on the same network as "..LOCATIONS[row]["PREFIX"].." which has a "..LOCATIONS[row]["LENGTH"].." bit length")
        end
    end

    trace.format("-- Address Unknown, unable to determine location --")
    return false
end

local function process_inbound_SDP(msg)
    -- process_inbound_SDP

    -- 1. Extract the IPv4 Address from the SDP
    local IPV4 = getAddress(msg)

    -- 2. Retreive a location name for the IPv4 Address
    local LOCATION = getLocation(IPV4)

    -- 3. Build the new Call-Info Header with the new information, if we have valid data.
    if LOCATION == false then
        trace.format("-- No Location found, proceeding without modification.")
    else
        local CallInfo = buildCallInfo(msg, LOCATION)

        if CallInfo then
            trace.format("-- Adding Call-Info Header")
            msg:addHeader("Call-Info", CallInfo)
        else
            trace.format("-- Could not build the Call-Info header, proceeding without modification.")
        end
    end
end

M.inbound_18X_INVITE = process_inbound_SDP
M.inbound_200_INVITE = process_inbound_SDP

return M
