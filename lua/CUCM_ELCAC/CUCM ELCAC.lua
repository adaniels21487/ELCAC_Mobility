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
    local LOC_COUNT = 9     -- Must match the amount of locations we have in our table.
    local LOCATIONS = {
        {["NAME"] = "LOC-TEST-1", ["PREFIX"]="192.168.100.8", ["LENGTH"]="30", ["PKID"]="62d8f58f-de7c-4cd0-afbf-2030ba52b743"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.100.0", ["LENGTH"]="24", ["PKID"]="106ab138-5a44-4a50-b7c4-3f8befd8f38c"},
        {["NAME"] = "LOC-TEST-3", ["PREFIX"]="192.169.0.0", ["LENGTH"]="16", ["PKID"]="3eed0571-38b7-4f09-9182-d1b8ad6b34cc"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.170.0.0", ["LENGTH"]="16", ["PKID"]="3eed0571-38b7-4f09-9182-d1b8ad6b34cc"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.171.0.0", ["LENGTH"]="16", ["PKID"]="3eed0571-38b7-4f09-9182-d1b8ad6b34cc"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.172.0.0", ["LENGTH"]="16", ["PKID"]="3eed0571-38b7-4f09-9182-d1b8ad6b34cc"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.173.0.0", ["LENGTH"]="16", ["PKID"]="3eed0571-38b7-4f09-9182-d1b8ad6b34cc"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.174.0.0", ["LENGTH"]="16", ["PKID"]="3eed0571-38b7-4f09-9182-d1b8ad6b34cc"},
        {["NAME"] = "LOC-TEST-2", ["PREFIX"]="192.168.0.0", ["LENGTH"]="16", ["PKID"]="3eed0571-38b7-4f09-9182-d1b8ad6b34cc"},
    }

    -- Gets get the bin of our IP.
    local BINSDP = ""
    for i in string.gfind(ADDRESS, "(%w+)") do
        BINSDP = BINSDP .. dec2bin(i,8)
    end

    -- Loop over our table looking for our location
    for row=1,LOC_COUNT do
        local BINPFX = ""
        for i in string.gfind(LOCATIONS[row]["PREFIX"], "(%w+)") do
            BINPFX = BINPFX .. dec2bin(i,8)
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
