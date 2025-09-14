library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity aes_core is
    port (
        clk     : in  std_logic;
        rst     : in  std_logic;
        start   : in  std_logic;
        key     : in  std_logic_vector(255 downto 0);
        data_in : in  std_logic_vector(127 downto 0);
        data_out: out std_logic_vector(127 downto 0);
        done    : out std_logic
    );
end aes_core;

architecture rtl of aes_core is
    -- Illustrative placeholder, not real AES. Do not use for production crypto.
    signal tmp : std_logic_vector(127 downto 0);
begin
    process(clk)
    begin
        if rising_edge(clk) then
            if rst = '1' then
                tmp <= (others => '0');
                done <= '0';
            elsif start = '1' then
                tmp <= data_in xor key(127 downto 0); -- Not real AES, just for testbench
                done <= '1';
            end if;
        end if;
    end process;
    data_out <= tmp;
end rtl;
