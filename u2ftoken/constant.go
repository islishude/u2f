package u2ftoken

const (
	CmdRegister     = 1
	CmdAuthenticate = 2
	CmdVersion      = 3
)

const (
	StatusNoError                = 0x9000
	StatusWrongLength            = 0x6700
	StatusInvalidData            = 0x6984
	StatusConditionsNotSatisfied = 0x6985
	StatusWrongData              = 0x6a80
	StatusInsNotSupported        = 0x6d00
)

const (
	tupRequired = 1 // Test of User Presence required
	tupConsume  = 2 // Consume a Test of User Presence
	tupTestOnly = 4 // Check valid key handle only, no test of user presence required

	authEnforce = tupRequired | tupConsume
	// This makes zero sense, but the check command is all three flags, not just tupTestOnly
	authCheckOnly = tupRequired | tupConsume | tupTestOnly
)
