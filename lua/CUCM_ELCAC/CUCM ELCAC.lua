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
--]]

M = {}
trace.enable()

local function getLocation(ADDRESS)
    -- From the supplied ADDRESS, return a Location Name and made up PKID.
	trace.format("-- Address: " .. ADDRESS .. " --")

	-- Create an empty RESPONSE hash, this will be returned.
	RESPONSE = {}

	-- Oh if only CUCM Lua would support math functions.
	if (ADDRESS == "123.123.123.123") then
		trace.format("-- Location: LOC-TEST-1 --")
		RESPONSE["NAME"] = "LOC-TEST-1"
		RESPONSE["PKID"] = "62d8f58f-de7c-4cd0-afbf-2030ba52b743"
	elseif (ADDRESS == "192.168.174.11") then
		trace.format("-- Location: LOC-TEST-2 --")
		RESPONSE["NAME"] = "LOC-TEST-2"
		RESPONSE["PKID"] = "106ab138-5a44-4a50-b7c4-3f8befd8f38c"
    elseif (ADDRESS == "192.168.174.10") then
        trace.format("-- Location: LOC-TEST-3 --")
        RESPONSE["NAME"] = "LOC-TEST-3"
        RESPONSE["PKID"] = "3eed0571-38b7-4f09-9182-d1b8ad6b34cc"
	else
		trace.format("-- Address Unknown, unable to determine location --")
		RESPONSE["NAME"] = "NULL"
	end

	return RESPONSE
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

--    local CINFO = "<urn:x-cisco-remotecc:callinfo>;x-cisco-loc-id=<GUID>;x-cisco-loc-name=<LOCATION_NAME>;x-cisco;fateshare;id=<FATESHARE-ID>;x-cisco-video-traffic-class=desktop"
    local CINFO = "<urn:x-cisco-remotecc:callinfo>;x-cisco-loc-id="..LOCATION["PKID"]..";x-cisco-loc-name="..LOCATION["NAME"]..";x-cisco;fateshare;id="..CID..";x-cisco-video-traffic-class=desktop"
    trace.format("-- Built Call-Info Header: " .. CINFO)

    return CINFO
end

local function dec2bin(dec)
    local result = ""
    local divres = dec / 2

    local part
    for i in string.gfind(divres, ".(5)") do
        part = i
    end

    if part == nil then
        trace.format("-- "..tostring(divres).." has no remainder")
    else
        trace.format("-- "..tostring(divres).." has remainder: " .. tostring(part))
    end
end

local function process_inbound_SDP(msg)
    -- process_inbound_SDP

    -- 1. Extract the IPv4 Address from the SDP
    local IPV4 = getAddress(msg)

    -- 2. Retreive a location name for the IPv4 Address
    local LOCATION = getLocation(IPV4)

    -- 3. Build the new Call-Info Header with the new information, if we have valid data.
    if LOCATION["NAME"] == "NULL" then
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

    trace.format("------------------------------------------")
--    trace.format("-- Dec to Bin: " .. bin("123"))
    dec2bin(12)
    dec2bin(13)
    trace.format("------------------------------------------")
end

M.inbound_18X_INVITE = process_inbound_SDP
M.inbound_200_INVITE = process_inbound_SDP

return M
