package hostid

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseIORegOutput(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name: "typical ioreg output",
			input: `+-o Root  <class IORegistryEntry, id 0x100000100, retain 32>
  +-o IOPlatformExpertDevice  <class IOPlatformExpertDevice, id 0x100000257, registered, matched, active, busy 0 (0 ms), retain 36>
      {
        "compatible" = <"MacBookPro18,2">
        "IOPlatformUUID" = "93DFC6F5-763D-5075-B305-8AC145D12F96"
        "IOPlatformSerialNumber" = "ABCDEF123456"
      }`,
			want: "93DFC6F5-763D-5075-B305-8AC145D12F96",
		},
		{
			name:  "tight spacing",
			input: `"IOPlatformUUID"="AAAA-BBBB"`,
			want:  "AAAA-BBBB",
		},
		{
			name:    "missing uuid",
			input:   `+-o IOPlatformExpertDevice { "compatible" = <"MacBookPro18,2"> }`,
			wantErr: true,
		},
		{
			name:    "empty",
			input:   ``,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseIORegOutput([]byte(tt.input))
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
