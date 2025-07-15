            byte[] k_ = new byte[] { 0xAB, 0xBB, 0xFC };

            for (int i = 0; i < b_.Length; i++)
            {
                b_[i] ^= k_[i % 3];
            }