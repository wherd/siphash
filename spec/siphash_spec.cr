require "./spec_helper"

describe "SipHash" do

    it "calculates the digest of and empty string" do
        SipHash.digest(0, 0, "").should eq 0x1e924b9d737700d7
    end

    it "calculates the digest of \"Hello world\"" do
        SipHash.digest(0, 0, "Hello world").should eq 0xc9e8a3021f3822d9
    end

    it "calculates the digest of 12345678123" do
        SipHash.digest(0, 0, "12345678123").should eq 0xf95d77ccdb0649f
    end

    it "calculates the digest of 8 zero bytes" do
        SipHash.digest(0, 0, "\0" * 8).should eq 0xe849e8bb6ffe2567
    end

    it "calculates the digest of 1535 zero bytes" do
        SipHash.digest(0, 0, "\0" * 1535).should eq 0xe74d1c0ab64b2afa
    end
end
