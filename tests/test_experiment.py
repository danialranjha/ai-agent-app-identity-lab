import unittest
from experiment import Engine, fixtures, mismatches

class PolicyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine=Engine().__enter__();cls.rows=cls.engine.run()
    @classmethod
    def tearDownClass(cls):cls.engine.__exit__()
    def select(self,id_,method):return next(r for r in self.rows if r['id']==id_ and r['method']==method)
    def test_all_independent_outcomes(self):self.assertEqual(mismatches(self.rows),[])
    def test_complete_pairs(self):self.assertEqual(len(self.rows),2*len(fixtures()))
    def test_same_blocked_identity_different_spelling(self):
        a=self.select('mixed-record','original-query-check');b=self.select('mixed-record','resolved-identity-check')
        self.assertEqual(a['capturedPID'],201);self.assertEqual(b['outcome'],'denied');self.assertNotIn('capturedPID',b)
        self.assertEqual(a['trace'][1],b['trace'][0])
    def test_both_policy_and_record_normalized(self):
        self.assertEqual(self.select('lastpass-lower','resolved-identity-check')['outcome'],'denied')
    def test_ordinary_target_preserved(self):
        for id_ in ['ordinary','ordinary-upper']:
            for m in ['original-query-check','resolved-identity-check']:self.assertEqual(self.select(id_,m)['capturedPID'],301)
    def test_no_unresolved_capture(self):
        for row in self.rows:
            if row['family']=='absent':self.assertEqual(row['outcome'],'not-found');self.assertNotIn('capturedPID',row)
    def test_denials_precede_capture(self):
        for row in self.rows:
            if row['outcome']=='denied':self.assertFalse(any(x.startswith('capture:') for x in row['trace']))
    def test_unlisted_app_limit(self):
        for m in ['original-query-check','resolved-identity-check']:self.assertEqual(self.select('unlisted-vault',m)['capturedPID'],401)
    def test_repeatable(self):self.assertEqual(self.rows,self.engine.run())
    def test_missing_check_detected(self):self.assertEqual(len(mismatches(self.engine.run('skip-check'))),27)
    def test_deny_all_detected(self):self.assertEqual(len(mismatches(self.engine.run('deny-all'))),3)
